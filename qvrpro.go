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

/*
   #include <stdlib.h>

   int hexToInt(char *hexString){
       return strtol(hexString, NULL, 0);
   }
*/
import "C"
import (
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

func convertHexToInt(hexString string) int {
	p := C.CString(hexString)
	defer C.free(unsafe.Pointer(p))

	n := C.hexToInt(p)
	return int(n)
}

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
	QvrElite                  = "qvrelite"
	QvrUnknown                = "unknown"
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

type Connection struct {
	url     string
	sid     string
	expire  int64
	timeout int64
	qvrApp  QvrApplication
}

var errorCodes map[int]string

var apiVersion = "1.2.0"
var apiPlayVersion = "v1"

var singletonConnection *Connection
var onceConnection sync.Once

//goland:noinspection GoUnusedExportedFunction
func Create(url string, qvrApp QvrApplication, timeout int64) *Connection {
	onceConnection.Do(func() {
		singletonConnection = &Connection{
			url:     url,
			expire:  0,
			timeout: timeout,
			sid:     "",
			qvrApp:  qvrApp,
		}

		errorCodes = make(map[int]string)

		errorCodes[convertHexToInt("0x93010002")] = "failed to open play session"
		errorCodes[convertHexToInt("0x93010006")] = "sid authentication failed"
		errorCodes[convertHexToInt("0x93010007")] = "failed to open session (session num full)"
		errorCodes[convertHexToInt("0x93010102")] = "start_time, end_time or time_val not specified"
		errorCodes[convertHexToInt("0x93010103")] = "channel_id not specified"
		errorCodes[convertHexToInt("0x93010104")] = "session_id not specified"
		errorCodes[convertHexToInt("0x93010107")] = "seek_time not specified"
		errorCodes[convertHexToInt("0x93010108")] = "session_id too long"
		errorCodes[convertHexToInt("0x93010109")] = "speed_num not specified"
		errorCodes[convertHexToInt("0x9301010B")] = "enable not specified"
		errorCodes[convertHexToInt("0x93010201")] = "failed to control stream"
		errorCodes[convertHexToInt("0x93010202")] = "session not found"
		errorCodes[convertHexToInt("0x93010203")] = "session is being closed"
		errorCodes[convertHexToInt("0x93010204")] = "no files found"
		errorCodes[convertHexToInt("0x93010003")] = "cmd is illegal"
		errorCodes[convertHexToInt("0x93010004")] = "insufficient memory"
		errorCodes[convertHexToInt("0x93000000")] = "Illegal Args"
		errorCodes[convertHexToInt("0x93000001")] = "Rejected Connection (DDOS)"
		errorCodes[convertHexToInt("0x93000002")] = "Exceeded Max Connection number"
		errorCodes[convertHexToInt("0x93000003")] = "Stream not ready"
		errorCodes[convertHexToInt("0x93000004")] = "Failed to start the stream"
		errorCodes[convertHexToInt("0x93000005")] = "Auth failed"
	})

	return singletonConnection
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
	baseUrl, err := url.Parse(connection.url)

	if err != nil {
		log.Println("Malformed URL: ", err.Error())
	} else {
		baseUrl.Path = "/cgi-bin/authLogin.cgi"

		params := url.Values{}
		params.Add("logout", "1")
		params.Add("sid", connection.sid)

		baseUrl.RawQuery = params.Encode()
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		log.Printf("[INFO] %s\n", baseUrl.String())

		response, err := client.Get(baseUrl.String())
		if err != nil {
			log.Print(err.Error())
		}

		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(response.Body)
	}

	connection.expire = 0
	connection.sid = ""
}

func (connection *Connection) Login(user string, password string) bool {

	if len(connection.sid) > 0 && connection.expire > time.Now().Unix() {
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
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	log.Printf("[INFO] %s\n", baseUrl.String())

	response, err := client.Get(baseUrl.String())
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
		log.Println(string(body))
		connection.Logout()
		return false
	}

	var qdoc QDocRoot
	log.Println(string(body))
	err = xml.Unmarshal(body, &qdoc)

	if nil != err {
		log.Print(err)
		log.Println(string(body))
		connection.Logout()
		return false
	}

	if qdoc.AuthPassed != 0 {
		connection.sid = qdoc.AuthSid
		connection.expire = time.Now().Unix() + connection.timeout
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
	params.Add("sid", connection.sid)
	params.Add("ver", apiVersion)

	baseUrl.RawQuery = params.Encode()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	log.Printf("[INFO] %s\n", baseUrl.String())

	response, err := client.Get(baseUrl.String())
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
	params.Add("sid", connection.sid)
	params.Add("ver", apiVersion)
	params.Add("act", "get_camera_capability")

	baseUrl.RawQuery = params.Encode()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	log.Printf("[INFO] %s\n", baseUrl.String())

	response, err := client.Get(baseUrl.String())
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

func (connection *Connection) CreateSessionId(channelId string, startTime int) (string, error) {
	baseUrl, err := url.Parse(connection.url)
	if err == nil {
		baseUrl.Path = connection.PlayPath()

		params := url.Values{}
		params.Add("cmd", "open")
		params.Add("sid", connection.sid)
		params.Add("ver", "v1")

		params.Add("ch_sid", channelId)
		params.Add("start_time", strconv.Itoa(startTime))
		params.Add("query_type", "0")
		params.Add("recording_type", "0")
		params.Add("stream", "0")
		params.Add("data_type", "0")

		baseUrl.RawQuery = params.Encode()
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		log.Printf("[INFO] %s\n", baseUrl.String())

		response, err := client.Get(baseUrl.String())

		if nil == err {
			defer func(Body io.ReadCloser) {
				_ = Body.Close()
			}(response.Body)

			bodyText, err := io.ReadAll(response.Body)
			if nil == err {
				v := strings.Split(string(bodyText), "\n")

				code, _ := strconv.Atoi(v[1])
				if code == 0 {
					return v[2], nil
				}
				message, exists := errorCodes[code]
				if exists {
					log.Println(message)
					err = errors.New(message)
				}
			} else {
				log.Println(err.Error())
			}
		} else {
			log.Println(err.Error())
		}
	}
	return "", err
}

func (connection *Connection) PlaySeek(sessionId string, seekTime int) (bool, error) {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		log.Println("Malformed URL: ", err.Error())
		return false, err
	}

	baseUrl.Path = connection.PlayPath()

	params := url.Values{}
	params.Add("cmd", "seek")
	params.Add("sid", connection.sid)
	params.Add("ver", apiPlayVersion)
	params.Add("session", sessionId)
	params.Add("seek_time", strconv.Itoa(seekTime))

	baseUrl.RawQuery = params.Encode()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	log.Printf("[INFO] %s\n", baseUrl.String())

	response, err := client.Get(baseUrl.String())

	if err != nil {
		return false, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	bodyText, err := io.ReadAll(response.Body)

	v := strings.Split(string(bodyText), "\n")

	code, _ := strconv.Atoi(v[1])
	if code != 0 {
		message, exists := errorCodes[code]
		if exists {
			return false, errors.New(message)
		}
	}

	return code == 0, nil
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
	params.Add("sid", connection.sid)
	params.Add("ver", apiPlayVersion)
	params.Add("session", sessionId)

	baseUrl.RawQuery = params.Encode()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	log.Printf("[INFO] %s\n", baseUrl.String())

	response, err := client.Get(baseUrl.String())

	if err != nil {
		return false, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	bodyText, err := io.ReadAll(response.Body)

	v := strings.Split(string(bodyText), "\n")

	code, _ := strconv.Atoi(v[1])
	if code != 0 {
		message, exists := errorCodes[code]
		if exists {
			log.Println(message)
			return false, errors.New(message)
		}
	}

	return code == 0, nil
}

//goland:noinspection GoUnusedConst
const (
	RecordingTypeOnlyAlarmFile = 1
	RecordingTypeNormalFile    = 1
	DataTypeJPeg               = 0
	DataTypeSource             = 1
)

// PlayGet
// 1. If data_type (parameter in Step 1) is '0'/DataTypeJPeg (JPEG)
// The frame is only a video frame
// ---
// [channel_name]\n
// [timestamp]\n // in UTC time format
// [jpeg image length]\n // INT
// [jpeg data] // BINARY, binary data of length [jpeg image length]
// ---
// 2. If data_type (parameter in Step 1) is '1'/DataTypeSource (source format of recording files)
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
	params.Add("sid", connection.sid)
	params.Add("ver", apiPlayVersion)
	params.Add("session", sessionId)
	params.Add("data_type", strconv.Itoa(dataType))

	baseUrl.RawQuery = params.Encode()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	log.Printf("[INFO] %s\n", baseUrl.String())

	response, err := client.Get(baseUrl.String())

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

func (connection *Connection) PlayFrame(writer http.ResponseWriter, channelId string, seekTime int) error {

	sessionId, err := connection.CreateSessionId(channelId, seekTime)
	if len(sessionId) == 0 {
		return err
	}

	success, err := connection.PlaySeek(sessionId, seekTime)
	if !success {
		return err
	}

	success, err = connection.Play(sessionId)
	if !success {
		return err
	}

	err = connection.PlayGet(writer, sessionId, DataTypeJPeg)

	return err
}

func (connection *Connection) LiveStream(writer http.ResponseWriter, channelId string, streamId string) error {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		return err
	}

	baseUrl.Path = connection.StreamsPath()

	params := url.Values{}
	params.Add("sid", connection.sid)
	params.Add("ch_sid", channelId)
	params.Add("stream_id", streamId)

	baseUrl.RawQuery = params.Encode()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	log.Printf("[INFO] %s\n", baseUrl.String())

	response, err := client.Get(baseUrl.String())

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

func (connection *Connection) Logs(logType uint, startTime int64, maxResults int) []LogEntry {
	qvrProLogEntry := make([]LogEntry, 0)

	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		// return errorResponse(http.StatusBadRequest, err.Error()), http.StatusBadRequest
		return qvrProLogEntry
	}

	baseUrl.Path = connection.LogsPath()

	params := url.Values{}
	params.Add("sid", connection.sid)
	if AllLogType != logType {
		params.Add("log_type", strconv.Itoa(int(logType)))
	}
	if startTime != 0 {
		params.Add("start_time", strconv.Itoa(int(startTime)))

	}
	params.Add("sort_field", "time")
	params.Add("max_results", strconv.Itoa(maxResults))
	params.Add("dir", "ASC")

	baseUrl.RawQuery = params.Encode()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	log.Printf("[INFO] %s\n", baseUrl.String())

	response, err := client.Get(baseUrl.String())

	if err != nil {
		return qvrProLogEntry
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	body, err := io.ReadAll(response.Body)
	var qvrResponse LogsResponse
	err = json.Unmarshal(body, &qvrResponse)
	if err != nil {
		return qvrProLogEntry
	}

	for i := range qvrResponse.Items {
		qvrResponse.Items[i].Application = connection.qvrApp
	}

	return qvrResponse.Items
}

func (connection *Connection) CameraSnapshot(channelId string, imageTs int) ([]byte, error) {
	baseUrl, err := url.Parse(connection.url)
	if err != nil {
		return nil, err
	}

	baseUrl.Path = connection.CameraSnapshotPath(channelId)

	params := url.Values{}
	params.Add("sid", connection.sid)
	params.Add("ver", apiVersion)
	params.Add("ts", strconv.Itoa(imageTs))

	baseUrl.RawQuery = params.Encode()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	log.Printf("[INFO] %s\n", baseUrl.String())

	response, err := client.Get(baseUrl.String())
	if err != nil {
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	body, _ := io.ReadAll(response.Body)

	return body, nil
}
