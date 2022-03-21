# Warning

This is a library is a work in progress.

Once it is release worthy I'll update this notice.


# Introduction


```
    connection := qvrpro.Create(qnapServer, qnapTimeout)
    if connection.Login(qnapUsername, qnapPassword) {
		logs := connection.Logs(qvrpro.SurveillanceEventsLogType, 0, 20)
		log.Println(logs)`
	}
``` 
