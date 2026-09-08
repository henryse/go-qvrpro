// **********************************************************************
//    Copyright (c) 2020-2022 Henry Seurer
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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ShutDownInfo struct {
	XMLName   xml.Name `xml:"shutdown_info"`
	Type      int64    `xml:"type"`
	TimeStamp int64    `xml:"timestamp"`
	Duration  int64    `xml:"duration"`
}

type QDocRoot struct {
	XMLName         xml.Name     `xml:"QDocRoot"`
	DoQuick         string       `xml:"doQuick"`
	IsBooting       string       `xml:"is_booting"`
	MediaReady      string       `xml:"mediaReady"`
	ShutdownInfo    ShutDownInfo `xml:"shutdown_info"`
	SMBFW           int          `xml:"SMBFW"`
	AuthPassed      int          `xml:"authPassed"`
	AuthSid         string       `xml:"authSid"`
	PwStatus        int          `xml:"pw_status"`
	IsAdmin         int          `xml:"isAdmin"`
	User            string       `xml:"username"`
	GroupName       string       `xml:"groupname"`
	TS              string       `xml:"ts"`
	FwNotice        int          `xml:"fwNotice"`
	SUID            string       `xml:"SUID"`
	Title           string       `xml:"title"`
	Content         string       `xml:"content"`
	PsType          int          `xml:"psType"`
	StandardMassage string       `xml:"standard_massage"`
	StandardColor   string       `xml:"standard_color"`
	StandardSize    string       `xml:"standard_size"`
	StandardBGStyle string       `xml:"standard_bg_style"`
	ShowVersion     int          `xml:"showVersion"`
	ShowLink        string       `xml:"show_link"`
	CUID            string       `xml:"cuid"`
}

type QvrApplication string

//goland:noinspection GoUnusedConst
const (
	QvrPro     QvrApplication = "qvrpro"
	QvrElite   QvrApplication = "qvrelite"
	QvrUnknown QvrApplication = "unknown"
)

//goland:noinspection GoUnusedExportedFunction
func QvrApplicationParse(app string) QvrApplication {
	switch strings.ToLower(app) {
	case "qvrpro":
		return QvrPro
	case "qvrelite":
		return QvrElite
	}
	return QvrUnknown
}

// Connection is safe to share between goroutines. The url, timeout, and
// qvrApp are written once by Create and only read afterward, the
// session id is guarded by mutex, and loginMutex serialises the login
// itself so that a burst of callers produces one session rather than one
// each.
type Connection struct {
	url     string
	timeout int64
	qvrApp  QvrApplication

	mutex  sync.Mutex
	sid    string
	expire int64

	loginMutex sync.Mutex

	// client bounds the whole exchange, streamClient is for the calls
	// whose body is a stream and so has no business being cut short.
	client       *http.Client
	streamClient *http.Client
}

// The play API reports failures in the body as an error code rather
// than as an HTTP status. The codes run past the top of a signed 32-bit
// int, hence the int64.
var errorCodes = map[int64]string{
	0x93010002: "failed to open play session",
	0x93010006: "sid authentication failed",
	0x93010007: "failed to open session (session num full)",
	0x93010102: "start_time, end_time or time_val not specified",
	0x93010103: "channel_id not specified",
	0x93010104: "session_id not specified",
	0x93010107: "seek_time not specified",
	0x93010108: "session_id too long",
	0x93010109: "speed_num not specified",
	0x9301010B: "enable not specified",
	0x93010201: "failed to control stream",
	0x93010202: "session not found",
	0x93010203: "session is being closed",
	0x93010204: "no files found",
	0x93010003: "cmd is illegal",
	0x93010004: "insufficient memory",
	0x93000000: "Illegal Args",
	0x93000001: "Rejected Connection (DDOS)",
	0x93000002: "Exceeded Max Connection number",
	0x93000003: "Stream not ready",
	0x93000004: "Failed to start the stream",
	0x93000005: "Auth failed",
}

const apiVersion = "1.2.0"
const apiPlayVersion = "v1"

// Nothing here waited for anything, a NAS that accepted the connection
// and then went quiet would hang the caller for good.
const (
	dialTimeout           = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 30 * time.Second

	// requestTimeout covers the request and the whole response, it is
	// not applied to the streaming calls.
	requestTimeout = 60 * time.Second
)

// QNAP serves the API with a self-signed certificate.
func newTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		MaxIdleConnsPerHost:   4,
	}
}

// jpegStartOfImage is the marker every JPEG frame opens with.
var jpegStartOfImage = []byte{0xFF, 0xD8, 0xFF}

// Connections are cached per server and application so that callers
// which ask for the same NAS share a session id, asking for a second
// NAS returns a second connection.
var (
	connectionsMutex sync.Mutex
	connections      = make(map[string]*Connection)
)

//goland:noinspection GoUnusedExportedFunction
func Create(url string, qvrApp QvrApplication, timeout int64) *Connection {
	key := fmt.Sprintf("%s/%s", url, qvrApp)

	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	connection, found := connections[key]

	if !found {
		// One transport per server, so that the connections to the NAS
		// are pooled and reused instead of built per request.
		transport := newTransport()

		connection = &Connection{
			url:          url,
			expire:       0,
			timeout:      timeout,
			sid:          "",
			qvrApp:       qvrApp,
			client:       &http.Client{Transport: transport, Timeout: requestTimeout},
			streamClient: &http.Client{Transport: transport},
		}

		connections[key] = connection
	}

	return connection
}

// sessionId returns the session id granted by the last login.
func (connection *Connection) sessionId() string {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()

	return connection.sid
}

// hasSession reports whether a login is still worth trusting.
func (connection *Connection) hasSession() bool {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()

	return len(connection.sid) > 0 && connection.expire > time.Now().Unix()
}

func (connection *Connection) setSession(sid string, expire int64) {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()

	connection.sid = sid
	connection.expire = expire
}

// takeSession clears the session and hands back what it was, so that a
// logout can hand it in without holding the lock over the request.
func (connection *Connection) takeSession() string {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()

	sid := connection.sid

	connection.sid = ""
	connection.expire = 0

	return sid
}

// The login carries the account password, and every other call carries
// the session id, neither belongs in a log file. The playback session id
// is left alone, it is scoped to one playback, and it is the thing worth
// following when a playback misbehaves.
var redactedParams = []string{"pwd", "sid"}

// redact returns the url as text with the secrets replaced, the url
// itself is left untouched.
func redact(target *url.URL) string {
	query := target.Query()
	hidden := false

	for _, name := range redactedParams {
		if len(query.Get(name)) > 0 {
			query.Set(name, "*****")
			hidden = true
		}
	}

	if !hidden {
		return target.String()
	}

	safe := *target
	safe.RawQuery = query.Encode()

	return safe.String()
}

// summarize trims a response body down to something loggable, the
// bodies are either short error documents or whole JPEG frames.
func summarize(body []byte) string {
	const limit = 256

	text := strings.TrimSpace(string(body))

	if len(text) > limit {
		return text[:limit]
	}

	return text
}

// readBody reads and closes a response, reporting anything the NAS did
// not answer with a 200 as an error.
func readBody(response *http.Response) ([]byte, error) {
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return body, fmt.Errorf("request failed with status %d: %s", response.StatusCode, summarize(body))
	}

	return body, nil
}

// The play API answers in plain text, the first line is the CGI
// version, the second is the result code, and "open" puts the session id
// on the third. A code of zero means the request worked.
func parsePlayResponse(body []byte) ([]string, error) {
	lines := strings.Split(string(body), "\n")

	if len(lines) < 2 {
		return lines, fmt.Errorf("play response has no result code: %s", summarize(body))
	}

	// A base of zero takes the code. However, QVR chose to write it, the
	// documented "0x…" form or plain decimal.
	code, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 0, 64)
	if err != nil {
		return lines, fmt.Errorf("play response has an unreadable result code: %s", summarize(body))
	}

	if code == 0 {
		return lines, nil
	}

	if message, exists := errorCodes[code]; exists {
		return lines, errors.New(message)
	}

	return lines, fmt.Errorf("play request failed with code 0x%08X", code)
}

func (connection *Connection) PlayPath() string {
	return fmt.Sprintf("/%s/apis/qplay.cgi", connection.qvrApp)
}

func (connection *Connection) StreamsPath() string {
	return fmt.Sprintf("/%s/streaming/getstream.cgi", connection.qvrApp)
}

func (connection *Connection) LogsPath() string {
	return fmt.Sprintf("/%s/logs/logs", connection.qvrApp)
}

func (connection *Connection) CameraListPath() string {
	return fmt.Sprintf("/%s/camera/list", connection.qvrApp)
}

func (connection *Connection) CameraCapabilityPath() string {
	return fmt.Sprintf("/%s/camera/capability", connection.qvrApp)
}

func (connection *Connection) CameraSnapshotPath(channelId string) string {
	return fmt.Sprintf("/%s/camera/snapshot/%s", connection.qvrApp, channelId)
}

func (connection *Connection) Logout() {
	sid := connection.takeSession()

	// Nothing was ever granted, so there is nothing to hand back. Login
	// calls us on its failure paths, this keeps those quiet.
	if len(sid) == 0 {
		return
	}

	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		log.Println("Malformed URL: ", err.Error())
		return
	}

	baseUrl.Path = "/cgi-bin/authLogin.cgi"

	params := url.Values{}
	params.Add("logout", "1")
	params.Add("sid", sid)

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())
	if err != nil {
		log.Print(err.Error())
		return
	}

	if _, err = readBody(response); err != nil {
		log.Print(err.Error())
	}
}

func (connection *Connection) Login(user string, password string) bool {
	// One login at a time, everybody else waits here and then finds the
	// session it granted.
	connection.loginMutex.Lock()
	defer connection.loginMutex.Unlock()

	if connection.hasSession() {
		return true
	}

	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		log.Println("Malformed URL: ", err.Error())
		connection.Logout()
		return false
	}

	baseUrl.Path = "/cgi-bin/authLogin.cgi"

	params := url.Values{}
	params.Add("serviceKey", "1")
	params.Add("pwd", password)
	params.Add("user", user)

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())
	if err != nil {
		log.Println("Get Failed: ", err.Error())
		connection.Logout()
		return false
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	body, err := io.ReadAll(response.Body)

	if nil != err {
		log.Print(err)
		connection.Logout()
		return false
	}

	// The body holds the session id on the way in, so only an
	// unreadable one is worth logging.
	var qdoc QDocRoot
	if err = xml.Unmarshal(body, &qdoc); nil != err {
		log.Printf("[ERROR] unable to read the login response: %s", summarize(body))
		connection.Logout()
		return false
	}

	if qdoc.AuthPassed != 0 {
		connection.setSession(qdoc.AuthSid, time.Now().Unix()+connection.timeout)
	} else {
		log.Print("Auth Failed")
	}

	return qdoc.AuthPassed != 0
}

func (connection *Connection) CameraList() ([]byte, error) {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		return nil, err
	}

	baseUrl.Path = connection.CameraListPath()

	params := url.Values{}
	params.Add("sid", connection.sessionId())
	params.Add("ver", apiVersion)

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())
	if err != nil {
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return nil, err
	}
	return body, nil
}

func (connection *Connection) CameraCapability() ([]byte, error) {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		return nil, err
	}

	baseUrl.Path = connection.CameraCapabilityPath()

	params := url.Values{}
	params.Add("sid", connection.sessionId())
	params.Add("ver", apiVersion)
	params.Add("act", "get_camera_capability")

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())
	if err != nil {
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return nil, err
	}
	return body, nil
}

// CreateSessionId opens a playback session at startTime, which is a UTC
// timestamp in milliseconds.
func (connection *Connection) CreateSessionId(channelId string, startTime int64) (string, error) {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		log.Println("Malformed URL: ", err.Error())
		return "", err
	}

	baseUrl.Path = connection.PlayPath()

	params := url.Values{}
	params.Add("cmd", "open")
	params.Add("sid", connection.sessionId())
	params.Add("ver", apiPlayVersion)

	params.Add("ch_sid", channelId)
	params.Add("start_time", strconv.FormatInt(startTime, 10))
	params.Add("query_type", "0")
	params.Add("recording_type", strconv.Itoa(RecordingTypeAllFiles))
	params.Add("data_type", strconv.Itoa(DataTypeJPeg))

	// The parameter table calls this one "stream_id" while the worked
	// example in the same document calls it "stream". Sending both is
	// harmless; a CGI ignores what it does not recognize.
	params.Add("stream", strconv.Itoa(StreamIdFirst))
	params.Add("stream_id", strconv.Itoa(StreamIdFirst))

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())
	if err != nil {
		log.Println(err.Error())
		return "", err
	}

	body, err := readBody(response)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}

	lines, err := parsePlayResponse(body)
	if err != nil {
		log.Println(err.Error())
		return "", err
	}

	if len(lines) < 3 || len(strings.TrimSpace(lines[2])) == 0 {
		err = fmt.Errorf("play open response has no session id: %s", summarize(body))
		log.Println(err.Error())
		return "", err
	}

	return strings.TrimSpace(lines[2]), nil
}

// PlaySeek moves a playback session to seekTime, which is a UTC
// timestamp in milliseconds.
func (connection *Connection) PlaySeek(sessionId string, seekTime int64) (bool, error) {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		log.Println("Malformed URL: ", err.Error())
		return false, err
	}

	baseUrl.Path = connection.PlayPath()

	params := url.Values{}
	params.Add("cmd", "seek")
	params.Add("sid", connection.sessionId())
	params.Add("ver", apiPlayVersion)
	params.Add("session", sessionId)
	params.Add("seek_time", strconv.FormatInt(seekTime, 10))

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())

	if err != nil {
		return false, err
	}

	body, err := readBody(response)
	if err != nil {
		return false, err
	}

	if _, err = parsePlayResponse(body); err != nil {
		return false, err
	}

	return true, nil
}

func (connection *Connection) Play(sessionId string) (bool, error) {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		log.Println("Malformed URL: ", err.Error())
		return false, err
	}

	baseUrl.Path = connection.PlayPath()

	params := url.Values{}
	params.Add("cmd", "play")
	params.Add("sid", connection.sessionId())
	params.Add("ver", apiPlayVersion)
	params.Add("session", sessionId)

	baseUrl.RawQuery = params.Encode()

	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())

	if err != nil {
		return false, err
	}

	body, err := readBody(response)
	if err != nil {
		return false, err
	}

	if _, err = parsePlayResponse(body); err != nil {
		log.Println(err.Error())
		return false, err
	}

	return true, nil
}

//goland:noinspection GoUnusedConst
const (
	RecordingTypeAllFiles      = 0
	RecordingTypeOnlyAlarmFile = 1
	RecordingTypeNormalFile    = 2

	DataTypeJPeg   = 0
	DataTypeSource = 1

	// StreamIdFirst Stream ids, the camera list reports which ones a channel has.
	StreamIdFirst  = 0
	StreamIdSecond = 2
	StreamIdThird  = 3
	StreamIdNone   = 16
	StreamIdAll    = 255
)

// PlayGet
// 1. If data_type (parameter in Step 1) is '0'/DataTypeJPeg (JPEG),
// The frame is only a video frame
// ---
// [channel_name]\n
// [timestamp]\n // in UTC time format
// [jpeg image length]\n // INT
// [jpeg data] // BINARY, binary data of length [jpeg image length]
// ---
// 2. If data_type (parameter in Step 1) is '1'/DataTypeSource (source format of recording files),
// A [media frame] is either a video or an audio frame. The format of [media
// frame] is the same as described in API "Live Streaming"

func (connection *Connection) PlayGet(writer http.ResponseWriter, sessionId string, dataType int) error {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		log.Println("Malformed URL: ", err.Error())
		return err
	}

	baseUrl.Path = connection.PlayPath()

	params := url.Values{}
	params.Add("cmd", "get")
	params.Add("sid", connection.sessionId())
	params.Add("ver", apiPlayVersion)
	params.Add("session", sessionId)
	params.Add("data_type", strconv.Itoa(dataType))

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	// A source data_type keeps sending frames, so this one is read
	// without a deadline on the body.
	response, err := connection.streamClient.Get(baseUrl.String())

	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	// set the header as per original stream
	for k, v := range response.Header {
		writer.Header().Set(k, v[0])
	}

	// stream the body to the client
	written, err := io.Copy(writer, response.Body)

	log.Printf("[INFO] Bytes written %d\n", written)

	return err
}

// PlayClose ends a playback session. QVR only allows a few sessions to
// be open at a time, "failed to open session (session num full)" is what
// it answers once they have been used up, so every session that is
// opened has to be handed back.
func (connection *Connection) PlayClose(sessionId string) error {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		log.Println("Malformed URL: ", err.Error())
		return err
	}

	baseUrl.Path = connection.PlayPath()

	params := url.Values{}
	params.Add("cmd", "close")
	params.Add("sid", connection.sessionId())
	params.Add("ver", apiPlayVersion)
	params.Add("session", sessionId)

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())

	if err != nil {
		return err
	}

	body, err := readBody(response)
	if err != nil {
		return err
	}

	_, err = parsePlayResponse(body)

	return err
}

// PlayFrame writes the recorded frame at seekTime, which is a UTC
// timestamp in milliseconds.
func (connection *Connection) PlayFrame(writer http.ResponseWriter, channelId string, seekTime int64) error {
	sessionId, err := connection.CreateSessionId(channelId, seekTime)
	if err != nil {
		return err
	}

	defer func() {
		if err := connection.PlayClose(sessionId); err != nil {
			log.Println(err)
		}
	}()

	if _, err = connection.PlaySeek(sessionId, seekTime); err != nil {
		return err
	}

	if _, err = connection.Play(sessionId); err != nil {
		return err
	}

	return connection.PlayGet(writer, sessionId, DataTypeJPeg)
}

func (connection *Connection) LiveStream(writer http.ResponseWriter, channelId string, streamId string) error {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		return err
	}

	baseUrl.Path = connection.StreamsPath()

	params := url.Values{}
	params.Add("sid", connection.sessionId())
	params.Add("ch_sid", channelId)
	params.Add("stream_id", streamId)

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	// A live stream runs until the caller goes away, so this one is
	// read without a deadline on the body.
	response, err := connection.streamClient.Get(baseUrl.String())

	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	// set the header as per original stream
	for k, v := range response.Header {
		writer.Header().Set(k, v[0])
	}

	// stream the body to the client
	written, err := io.Copy(writer, response.Body)

	log.Printf("[INFO] Bytes written %d\n", written)

	return err
}

type LogEntry struct {
	UTCTime         int64          `json:"UTC_time"`
	UTCTimeS        string         `json:"UTC_time_s"`
	Content         string         `json:"content"`
	Level           int            `json:"level"`
	LogID           int            `json:"log_id"`
	LogType         int            `json:"log_type"`
	NasIP           string         `json:"nas_ip"`
	NasName         string         `json:"nas_name"`
	ServerTime      int64          `json:"server_time"`
	SourceIP        string         `json:"source_ip"`
	SourceName      string         `json:"source_name"`
	Time            string         `json:"time"`
	Timezone        string         `json:"timezone"`
	TimezoneOrder   int            `json:"timezone_order"`
	User            string         `json:"user"`
	Action          string         `json:"action,omitempty"`
	Args            []string       `json:"args,omitempty"`
	ChannelID       int            `json:"channel_id,omitempty"`
	EventID         int            `json:"event_id,omitempty"`
	GlobalChannelID string         `json:"global_channel_id,omitempty"`
	MainType        int            `json:"main_type,omitempty"`
	SubType         int            `json:"sub_type,omitempty"`
	SubTypeOrder    int            `json:"sub_type_order,omitempty"`
	Application     QvrApplication `json:"application,omitempty"`
}

type LogsResponse struct {
	Code          int        `json:"code"`
	Items         []LogEntry `json:"items"`
	Mesg          string     `json:"mesg"`
	ResponseItems int        `json:"responseItems"`
	TotalItems    int        `json:"totalItems"`
}

//goland:noinspection GoUnusedConst
const (
	AllLogType                     = 0
	SystemEventsLogType            = 1
	SystemConnectionsLogType       = 2
	SurveillanceEventsLogType      = 3
	SurveillanceConnectionsLogType = 4
	SurveillanceSettingsLogType    = 5
)

// Logs returns up to maxResults log entries recorded since startTime,
// which is a UTC timestamp in milliseconds, use zero for no lower bound.
// The entries are the oldest ones in the window, they are sorted by
// ascending time.
func (connection *Connection) Logs(logType uint, startTime int64, maxResults int) ([]LogEntry, error) {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		return nil, err
	}

	baseUrl.Path = connection.LogsPath()

	params := url.Values{}
	params.Add("sid", connection.sessionId())
	if AllLogType != logType {
		params.Add("log_type", strconv.Itoa(int(logType)))
	}
	if startTime != 0 {
		params.Add("start_time", strconv.FormatInt(startTime, 10))
	}
	params.Add("sort_field", "time")
	params.Add("max_results", strconv.Itoa(maxResults))
	params.Add("dir", "ASC")

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())

	if err != nil {
		return nil, err
	}

	body, err := readBody(response)
	if err != nil {
		return nil, err
	}

	var qvrResponse LogsResponse
	if err = json.Unmarshal(body, &qvrResponse); err != nil {
		return nil, fmt.Errorf("unable to read the log response: %s", summarize(body))
	}

	// The logs CGI reports its own result in the body, an empty item
	// list on its own is a perfectly good answer.
	if qvrResponse.Code != 0 && qvrResponse.Code != http.StatusOK {
		return nil, fmt.Errorf("log request failed with code %d: %s", qvrResponse.Code, qvrResponse.Mesg)
	}

	for i := range qvrResponse.Items {
		qvrResponse.Items[i].Application = connection.qvrApp
	}

	return qvrResponse.Items, nil
}

// CameraSnapshot returns the JPEG the camera recorded at imageTs, which
// is a UTC timestamp in milliseconds. QVR returns the current frame when
// imageTs is zero and only honors it from API version 1.2.0 onwards.
func (connection *Connection) CameraSnapshot(channelId string, imageTs int64) ([]byte, error) {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		return nil, err
	}

	baseUrl.Path = connection.CameraSnapshotPath(channelId)

	params := url.Values{}
	params.Add("sid", connection.sessionId())
	params.Add("ver", apiVersion)
	if imageTs != 0 {
		params.Add("image_ts", strconv.FormatInt(imageTs, 10))
	}

	baseUrl.RawQuery = params.Encode()
	log.Printf("[INFO] %s\n", redact(baseUrl))

	response, err := connection.client.Get(baseUrl.String())
	if err != nil {
		return nil, err
	}

	body, err := readBody(response)
	if err != nil {
		return nil, err
	}

	// QVR reports a refused snapshot as a JSON error document with a
	// 200, so the frame has to be recognized before it is handed back.
	if !bytes.HasPrefix(body, jpegStartOfImage) {
		return nil, fmt.Errorf("snapshot of %s is not a jpeg: %s", channelId, summarize(body))
	}

	return body, nil
}
