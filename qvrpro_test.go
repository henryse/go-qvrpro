// **********************************************************************
//    Copyright (c) 2020-2026 Henry Seurer
//
//    Permission is hereby granted, free of charge, to any person
//    obtaining a copy of this software and associated documentation
//    files (the "Software"), to deal in the Software without
//    restriction, including without limitation the rights to use,
//    copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the
//    Software is furnished to do so, subject to the following
//    conditions:
//
//    The above copyright notice and this permission notice shall be
//    included in all copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
//    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
//    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
//    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//    OTHER DEALINGS IN THE SOFTWARE.
//
// **********************************************************************

package qvrpro

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var jpegBody = append([]byte{0xFF, 0xD8, 0xFF}, []byte("frame")...)

// A truncated or unexpected play response used to index past the end of
// the split body.
func TestParsePlayResponseRejectsShortBodies(t *testing.T) {
	for _, body := range []string{"", "\n", "v1", "v1\n", "v1\nnonsense\n", "garbage"} {
		if _, err := parsePlayResponse([]byte(body)); err == nil {
			t.Fatalf("expected an error for %q", body)
		}
	}
}

func TestParsePlayResponseReadsTheSession(t *testing.T) {
	lines, err := parsePlayResponse([]byte("v1\n0\nSESSION123\n"))
	if err != nil {
		t.Fatal(err)
	}

	if lines[2] != "SESSION123" {
		t.Fatalf("bad session line %q", lines[2])
	}
}

// An error code the table does not know about is still an error.
func TestParsePlayResponseReportsUnknownCodes(t *testing.T) {
	_, err := parsePlayResponse([]byte("v1\n123456\n"))

	if err == nil || !strings.Contains(err.Error(), "123456") {
		t.Fatalf("unmapped code should be reported: %v", err)
	}
}

// Login calls Logout on its failure paths, which used to dereference a
// nil response when the NAS could not be reached.
func TestLogoutSurvivesAnUnreachableServer(t *testing.T) {
	connection := Create("http://127.0.0.1:1", QvrPro, 60)

	if connection.Login("device", "secret") {
		t.Fatal("login should have failed")
	}

	connection.Logout()
}

func TestCreateReturnsAConnectionPerServer(t *testing.T) {
	first := Create("https://heimdall.example", QvrPro, 60)
	second := Create("https://mimir.example", QvrElite, 60)
	again := Create("https://heimdall.example", QvrPro, 60)

	if first == second {
		t.Fatal("two servers must not share a connection")
	}

	if first != again {
		t.Fatal("the same server must reuse its connection")
	}

	if second.url != "https://mimir.example" || second.qvrApp != QvrElite {
		t.Fatalf("wrong connection returned: %s %s", second.url, second.qvrApp)
	}
}

func qvrServer(t *testing.T, snapshotQuery *string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "authLogin"):
			if request.URL.Query().Get("logout") == "1" {
				_, _ = writer.Write([]byte(`<QDocRoot></QDocRoot>`))
				return
			}
			_, _ = writer.Write([]byte(`<QDocRoot><authPassed>1</authPassed><authSid>SID42</authSid></QDocRoot>`))

		case strings.Contains(request.URL.Path, "camera/snapshot/refused"):
			// QVR reports a refused snapshot as JSON with a 200.
			_, _ = writer.Write([]byte(`{"error":{"code":"0xB1000006"}}`))

		case strings.Contains(request.URL.Path, "camera/snapshot/"):
			*snapshotQuery = request.URL.RawQuery
			_, _ = writer.Write(jpegBody)

		case strings.Contains(request.URL.Path, "logs/logs"):
			if request.URL.Query().Get("log_type") == "9" {
				writer.WriteHeader(http.StatusForbidden)
				_, _ = writer.Write([]byte(`{"code":403,"mesg":"no permission"}`))
				return
			}
			_, _ = writer.Write([]byte(`{"code":200,"items":[{"UTC_time":1444436555000,"content":"Motion detected"}]}`))

		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestLogsReportsFailures(t *testing.T) {
	var snapshotQuery string
	server := qvrServer(t, &snapshotQuery)
	defer server.Close()

	connection := Create(server.URL+"/logs", QvrPro, 60)
	if !connection.Login("device", "secret") {
		t.Fatal("login failed")
	}

	entries, err := connection.Logs(SurveillanceEventsLogType, 1444436555000, 10)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 || entries[0].UTCTime != 1444436555000 || entries[0].Application != QvrPro {
		t.Fatalf("bad entries %v", entries)
	}

	if _, err = connection.Logs(9, 0, 10); err == nil {
		t.Fatal("a 403 from the logs CGI should be an error")
	}
}

func TestCameraSnapshotAsksForTheRecordedFrame(t *testing.T) {
	var snapshotQuery string
	server := qvrServer(t, &snapshotQuery)
	defer server.Close()

	connection := Create(server.URL+"/snapshot", QvrPro, 60)
	if !connection.Login("device", "secret") {
		t.Fatal("login failed")
	}

	image, err := connection.CameraSnapshot("channel6", 1444436555000)
	if err != nil {
		t.Fatal(err)
	}

	if string(image) != string(jpegBody) {
		t.Fatalf("bad image %q", image)
	}

	if !strings.Contains(snapshotQuery, "image_ts=1444436555000") {
		t.Fatalf("the snapshot must be asked for by image_ts: %s", snapshotQuery)
	}

	// A zero timestamp means "whatever the camera sees now".
	if _, err = connection.CameraSnapshot("channel6", 0); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(snapshotQuery, "image_ts") {
		t.Fatalf("a zero timestamp should be left out: %s", snapshotQuery)
	}

	if _, err = connection.CameraSnapshot("refused", 0); err == nil {
		t.Fatal("a json error document is not an image")
	}

	connection.Logout()

	if len(connection.sid) != 0 {
		t.Fatal("logout should clear the session")
	}
}

// One transport per server, pooled and reused, with a deadline on
// everything except the calls whose body is a stream.
func TestConnectionSharesOneBoundedClient(t *testing.T) {
	connection := Create("https://timeouts.example", QvrPro, 60)

	if connection.client.Timeout != requestTimeout {
		t.Fatalf("request client has no deadline: %v", connection.client.Timeout)
	}

	if connection.streamClient.Timeout != 0 {
		t.Fatalf("a stream must not be cut short: %v", connection.streamClient.Timeout)
	}

	if connection.client.Transport != connection.streamClient.Transport {
		t.Fatal("both clients should share the pooled transport")
	}

	transport, ok := connection.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport %T", connection.client.Transport)
	}

	if transport.ResponseHeaderTimeout != responseHeaderTimeout || transport.TLSHandshakeTimeout != tlsHandshakeTimeout {
		t.Fatal("the transport should bound the handshake and the wait for headers")
	}
}

// A burst of callers should produce one login, not one each, and the
// session must be readable from every goroutine.
func TestConcurrentUseIsSerialised(t *testing.T) {
	var (
		mutex  sync.Mutex
		logins int
	)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "authLogin"):
			mutex.Lock()
			logins++
			mutex.Unlock()
			_, _ = writer.Write([]byte(`<QDocRoot><authPassed>1</authPassed><authSid>SID42</authSid></QDocRoot>`))

		case strings.Contains(request.URL.Path, "camera/snapshot/"):
			if request.URL.Query().Get("sid") != "SID42" {
				t.Errorf("snapshot without a session: %s", request.URL.RawQuery)
			}
			_, _ = writer.Write(jpegBody)

		default:
			_, _ = writer.Write([]byte(`{"code":200,"items":[]}`))
		}
	}))
	defer server.Close()

	connection := Create(server.URL+"/concurrent", QvrPro, 60)

	var waitGroup sync.WaitGroup
	for i := 0; i < 20; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()

			if !connection.Login("device", "secret") {
				t.Error("login failed")
				return
			}

			if _, err := connection.Logs(SurveillanceEventsLogType, 0, 10); err != nil {
				t.Error(err)
			}

			if _, err := connection.CameraSnapshot("channel6", 1444436555000); err != nil {
				t.Error(err)
			}
		}()
	}
	waitGroup.Wait()

	mutex.Lock()
	defer mutex.Unlock()

	if logins != 1 {
		t.Fatalf("expected one login for twenty callers, got %d", logins)
	}
}

// Every playback session that is opened has to be handed back.
func TestPlayFrameClosesItsSession(t *testing.T) {
	var (
		mutex sync.Mutex
		cmds  []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "authLogin") {
			_, _ = writer.Write([]byte(`<QDocRoot><authPassed>1</authPassed><authSid>SID42</authSid></QDocRoot>`))
			return
		}

		cmd := request.URL.Query().Get("cmd")

		mutex.Lock()
		cmds = append(cmds, cmd)
		mutex.Unlock()

		switch cmd {
		case "open":
			_, _ = writer.Write([]byte("v1\n0\nSESSION123\n"))
		case "get":
			_, _ = writer.Write([]byte("channel6\n1444436555000\n8\nframe123"))
		default:
			if request.URL.Query().Get("session") != "SESSION123" {
				t.Errorf("%s used the wrong session: %s", cmd, request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte("v1\n0\n"))
		}
	}))
	defer server.Close()

	connection := Create(server.URL+"/play", QvrPro, 60)
	if !connection.Login("device", "secret") {
		t.Fatal("login failed")
	}

	recorder := httptest.NewRecorder()
	if err := connection.PlayFrame(recorder, "channel6", 1444436555000); err != nil {
		t.Fatal(err)
	}

	mutex.Lock()
	defer mutex.Unlock()

	if strings.Join(cmds, ",") != "open,seek,play,get,close" {
		t.Fatalf("unexpected play sequence: %v", cmds)
	}
}

// A failure part way through still has to hand the session back.
func TestPlayFrameClosesItsSessionAfterAFailure(t *testing.T) {
	var (
		mutex  sync.Mutex
		closed bool
	)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "authLogin") {
			_, _ = writer.Write([]byte(`<QDocRoot><authPassed>1</authPassed><authSid>SID42</authSid></QDocRoot>`))
			return
		}

		switch request.URL.Query().Get("cmd") {
		case "open":
			_, _ = writer.Write([]byte("v1\n0\nSESSION123\n"))
		case "seek":
			// 0x93010107, seek_time not specified.
			_, _ = writer.Write([]byte("v1\n" + strconv.Itoa(convertHexToInt("0x93010107")) + "\n"))
		case "close":
			mutex.Lock()
			closed = true
			mutex.Unlock()
			_, _ = writer.Write([]byte("v1\n0\n"))
		default:
			t.Errorf("nothing else should have been called: %s", request.URL.RawQuery)
		}
	}))
	defer server.Close()

	connection := Create(server.URL+"/playfail", QvrPro, 60)
	if !connection.Login("device", "secret") {
		t.Fatal("login failed")
	}

	recorder := httptest.NewRecorder()
	err := connection.PlayFrame(recorder, "channel6", 1444436555000)

	if err == nil || !strings.Contains(err.Error(), "seek_time") {
		t.Fatalf("the seek failure should have been reported: %v", err)
	}

	mutex.Lock()
	defer mutex.Unlock()

	if !closed {
		t.Fatal("the session was left open")
	}
}
