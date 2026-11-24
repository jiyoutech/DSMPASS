package provider

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Each snapshot reads independent departments or users in small windows. Pages
// for the same department still follow its cursor in the original order.
const directoryReadConcurrency = 4

func readDirectoryItems[I, O any](items []I, read func(I) (O, error)) ([]O, error) {
	out := make([]O, len(items))
	width := directoryReadConcurrency
	for start := 0; start < len(items); {
		count := min(width, len(items)-start)
		errs := make([]error, count)
		var wg sync.WaitGroup
		for i := range count {
			wg.Go(func() { out[start+i], errs[i] = read(items[start+i]) })
		}
		wg.Wait()
		var delay time.Duration
		for _, err := range errs {
			if err == nil {
				continue
			}
			var limit *directoryRateLimit
			if !errors.As(err, &limit) || limit.delay > 30*time.Second {
				return nil, err
			}
			delay = max(delay, limit.delay)
		}
		if delay > 0 {
			// Honor the longest Retry-After, retry only the failed reads once and
			// leave the remaining work sequential for this phase.
			width = 1
			time.Sleep(delay)
			for i, err := range errs {
				if err == nil {
					continue
				}
				out[start+i], err = read(items[start+i])
				if err != nil {
					return nil, err
				}
			}
		}
		start += count
	}
	return out, nil
}

type directoryRateLimit struct {
	error
	delay time.Duration
}

func (e *directoryRateLimit) Unwrap() error { return e.error }

func directoryHTTPError(response *http.Response, err error) error {
	if response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusGatewayTimeout {
		return &temporaryDirectoryError{err}
	}
	if response.StatusCode != http.StatusTooManyRequests {
		return err
	}
	delay := time.Second
	value := response.Header.Get("Retry-After")
	if seconds, parseErr := strconv.ParseUint(value, 10, 32); parseErr == nil {
		delay = max(time.Millisecond, time.Duration(seconds)*time.Second)
	} else if until, parseErr := http.ParseTime(value); parseErr == nil {
		delay = max(time.Millisecond, time.Until(until))
	}
	return &directoryRateLimit{err, delay}
}

// Retry the failed read-only page at the same cursor. Rate limits are handled
// by the bounded directory reader using the provider's Retry-After delay.
type temporaryDirectoryError struct{ error }

func (e *temporaryDirectoryError) Unwrap() error { return e.error }

func readDirectoryPage(read func() (map[string]any, error)) (map[string]any, error) {
	page, err := read()
	var network net.Error
	var temporary *temporaryDirectoryError
	if err != nil && !errors.Is(err, context.Canceled) && (errors.As(err, &temporary) || errors.As(err, &network) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
		return read()
	}
	return page, err
}

func directoryPageItems(data map[string]any, key string) ([]map[string]any, error) {
	raw, ok := data[key].([]any)
	if !ok {
		return nil, errors.New("通讯录分页缺少记录列表")
	}
	items := mapItems(data, key)
	if len(raw) != len(items) {
		return nil, errors.New("通讯录分页包含无效记录")
	}
	return items, nil
}

// Some older responses omit has_more on a terminal page.
func directoryPageHasMore(data map[string]any, cursor string) (bool, error) {
	if more, ok := data["has_more"].(bool); ok {
		return more, nil
	}
	if _, invalid := data["has_more"]; invalid || firstStringish(data, cursor) != "" {
		return false, errors.New("通讯录分页缺少有效的结束标志")
	}
	return false, nil
}
