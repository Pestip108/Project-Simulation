package logs

type LogEvent struct {
	Action    string `json:"action"`
	Timestamp int64  `json:"timestamp"`
}
