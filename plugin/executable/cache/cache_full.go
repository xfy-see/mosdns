//go:build !mosdns_minimal

/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package cache

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	minimumChangesToDump   = 1024
	dumpHeader             = "mosdns_cache_v2"
	dumpBlockSize          = 128
	dumpMaximumBlockLength = 1 << 20
)

type cacheBuildState struct {
	closeOnce   sync.Once
	closeNotify chan struct{}
	updatedKey  atomic.Uint64
}

func (a *Args) initDumpArgs()                { utils.SetDefaultUnsignNum(&a.DumpInterval, 600) }
func validateCacheArgs(a *Args) error        { return nil }
func (c *Cache) registerAPI(bp *coremain.BP) { bp.RegAPI(c.Api()) }
func (c *Cache) recordUpdate()               { c.updatedKey.Add(1) }
func (c *Cache) initBuildFeatures() {
	c.closeNotify = make(chan struct{})
	if err := c.loadDump(); err != nil {
		c.logger.Error("failed to load cache dump", zap.Error(err))
	}
	c.startDumpLoop()
}
func (c *Cache) closeBuildFeatures() {
	if err := c.dumpCache(); err != nil {
		c.logger.Error("failed to dump cache", zap.Error(err))
	}
	c.closeOnce.Do(func() { close(c.closeNotify) })
}

func (c *Cache) loadDump() error {
	if len(c.args.DumpFile) == 0 {
		return nil
	}
	f, err := os.Open(c.args.DumpFile)
	if err != nil {
		return err
	}
	defer f.Close()
	en, err := c.readDump(f)
	if err != nil {
		return err
	}
	c.logger.Info("cache dump loaded", zap.Int("entries", en))
	return nil
}

// startDumpLoop starts a dump loop in another goroutine. It does not block.
func (c *Cache) startDumpLoop() {
	if len(c.args.DumpFile) == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Duration(c.args.DumpInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Check if we have enough changes to dump.
				keyUpdated := c.updatedKey.Swap(0)
				if keyUpdated < minimumChangesToDump { // Nop.
					c.updatedKey.Add(keyUpdated)
					continue
				}

				if err := c.dumpCache(); err != nil {
					c.logger.Error("dump cache", zap.Error(err))
				}
			case <-c.closeNotify:
				return
			}
		}
	}()
}

func (c *Cache) dumpCache() error {
	if len(c.args.DumpFile) == 0 {
		return nil
	}

	f, err := os.Create(c.args.DumpFile)
	if err != nil {
		return err
	}
	defer f.Close()

	en, err := c.writeDump(f)
	if err != nil {
		return fmt.Errorf("failed to write dump, %w", err)
	}
	c.logger.Info("cache dumped", zap.Int("entries", en))
	return nil
}

func (c *Cache) Api() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/flush", func(w http.ResponseWriter, req *http.Request) {
		c.backend.Flush()
	})
	r.Get("/dump", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("content-type", "application/octet-stream")
		_, err := c.writeDump(w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	r.Post("/load_dump", func(w http.ResponseWriter, req *http.Request) {
		if _, err := c.readDump(req.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return r
}

func (c *Cache) writeDump(w io.Writer) (int, error) {
	en := 0

	gw, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	gw.Name = dumpHeader

	block := new(dumpBlock)
	writeBlock := func() error {
		b := marshalDumpBlock(block)

		l := make([]byte, 8)
		binary.BigEndian.PutUint64(l, uint64(len(b)))
		_, err := gw.Write(l)
		if err != nil {
			return fmt.Errorf("failed to write header, %w", err)
		}
		_, err = gw.Write(b)
		if err != nil {
			return fmt.Errorf("failed to write data, %w", err)
		}

		en += len(block.Entries)
		clear(block.Entries)
		block.Entries = block.Entries[:0]
		return nil
	}

	now := time.Now()
	rangeFunc := func(k key, v *item, cacheExpirationTime time.Time) error {
		if cacheExpirationTime.Before(now) {
			return nil
		}
		msg, err := v.resp.Pack()
		if err != nil {
			return fmt.Errorf("failed to pack msg, %w", err)
		}
		e := &dumpEntry{
			Key:                 []byte(k),
			CacheExpirationTime: cacheExpirationTime.Unix(),
			MsgExpirationTime:   v.expirationTime.Unix(),
			MsgStoredTime:       v.storedTime.Unix(),
			Msg:                 msg,
		}
		block.Entries = append(block.Entries, e)

		// Block is big enough for a write operation.
		if len(block.Entries) >= dumpBlockSize {
			return writeBlock()
		}
		return nil
	}
	if err := c.backend.Range(rangeFunc); err != nil {
		return en, err
	}

	if len(block.Entries) > 0 {
		if err := writeBlock(); err != nil {
			return en, err
		}
	}
	return en, gw.Close()
}

// readDump reads dumped data from r. It returns the number of bytes read,
// number of entries read and any error encountered.
func (c *Cache) readDump(r io.Reader) (int, error) {
	en := 0
	gr, err := gzip.NewReader(r)
	if err != nil {
		return en, fmt.Errorf("failed to read gzip header, %w", err)
	}
	if gr.Name != dumpHeader {
		return en, fmt.Errorf("invalid or old cache dump, header is %s, want %s", gr.Name, dumpHeader)
	}

	var errReadHeaderEOF = errors.New("")
	readBlock := func() error {
		h := pool.GetBuf(8)
		defer pool.ReleaseBuf(h)
		_, err := io.ReadFull(gr, *h)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errReadHeaderEOF
			}
			return fmt.Errorf("failed to read block header, %w", err)
		}
		u := binary.BigEndian.Uint64(*h)
		if u > dumpMaximumBlockLength {
			return fmt.Errorf("invalid header, block length is big, %d", u)
		}

		b := pool.GetBuf(int(u))
		defer pool.ReleaseBuf(b)
		_, err = io.ReadFull(gr, *b)
		if err != nil {
			return fmt.Errorf("failed to read block data, %w", err)
		}

		block, err := unmarshalDumpBlock(*b)
		if err != nil {
			return fmt.Errorf("failed to decode block data, %w", err)
		}

		en += len(block.Entries)
		for _, entry := range block.Entries {
			cacheExpTime := time.Unix(entry.CacheExpirationTime, 0)
			msgExpTime := time.Unix(entry.MsgExpirationTime, 0)
			storedTime := time.Unix(entry.MsgStoredTime, 0)
			resp := new(dns.Msg)
			if err := resp.Unpack(entry.Msg); err != nil {
				return fmt.Errorf("failed to decode dns msg, %w", err)
			}
			if !validDumpKey(entry.Key, resp) {
				continue
			}

			i := &item{
				resp:           resp,
				storedTime:     storedTime,
				expirationTime: msgExpTime,
			}
			c.backend.Store(key(entry.Key), i, cacheExpTime)
		}
		return nil
	}

	for {
		err = readBlock()
		if err != nil {
			if err == errReadHeaderEOF {
				err = nil // This is expected if there is no block to read.
			}
			break
		}
	}

	if err != nil {
		return en, err
	}
	return en, gr.Close()
}

// validDumpKey checks the encoded question against the stored response. Old
// writers discarded the high QTYPE byte and did not distinguish DNS classes;
// loading those entries under their legacy keys could serve a different query.
func validDumpKey(msgKey []byte, response *dns.Msg) bool {
	if len(msgKey) < 4 || len(response.Question) != 1 {
		return false
	}
	question := response.Question[0]
	return question.Qclass == dns.ClassINET &&
		msgKey[0]&^byte(7) == 0 &&
		msgKey[1] == byte(question.Qtype>>8) &&
		msgKey[2] == byte(question.Qtype) &&
		msgKey[3] == byte(len(question.Name)) &&
		bytes.EqualFold(msgKey[4:], []byte(question.Name))
}
