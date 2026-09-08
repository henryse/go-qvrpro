# Warning

This is a library is a work in progress.

Once it is release worthy, I'll update this notice.


# Introduction

```
    connection := qvrpro.Create(qnapServer, qvrpro.QvrPro, qnapSessionSeconds)
    if connection.Login(qnapUsername, qnapPassword) {
        logs := connection.Logs(qvrpro.SurveillanceEventsLogType, time.Now().UnixMilli()-oneHourMs, 20)
        log.Println(logs)
    }
```

`Create` caches one connection per server and application, so calling it
again for the same NAS reuses the session id, and calling it for another
NAS returns another connection.

Every timestamp in this API, the log `start_time`, the playback
`start_time` and `seek_time`, and the snapshot `image_ts`, is a UTC time
in milliseconds.

The QNAP API documentation this library was written against is in the
`api` directory, the same documents are published here:

```
https://petstore.swagger.io/?url=https://download.qnap.com/apidoc/qvrpro/qvr_pro_api_1.0.0.yaml
https://petstore.swagger.io/?url=https://download.qnap.com/apidoc/qvrpro/qvr_pro_api_1.1.0.yaml
https://petstore.swagger.io/?url=https://download.qnap.com/apidoc/qvrpro/qvr_pro_api_1.2.0.yaml
```
