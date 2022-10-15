# iprepd-firewall

[![Go Report Card](https://goreportcard.com/badge/github.com/adrianosela/iprepd-firewall)](https://goreportcard.com/report/github.com/adrianosela/iprepd-firewall)
[![GitHub issues](https://img.shields.io/github/issues/adrianosela/iprepd-firewall.svg)](https://github.com/adrianosela/iprepd-firewall/issues)
[![Documentation](https://godoc.org/github.com/adrianosela/iprepd-firewall/fwmw?status.svg)](https://godoc.org/github.com/adrianosela/iprepd-firewall/fwmw)
[![license](https://img.shields.io/github/license/adrianosela/iprepd-firewall.svg)](https://github.com/adrianosela/iprepd-firewall/blob/master/LICENSE)

Seamless IP reputation based firewall in the form of an HTTP middleware -- using an [IPrepd](https://github.com/mozilla-services/iprepd) server as the source of truth

### Usage

> **NOTE** that full examples can be found in the ```/examples``` directory

* Create a [fwmw.Firewall](https://godoc.org/github.com/adrianosela/iprepd-firewall/fwmw#Firewall) struct with the appropriate configuration

```
fw := fwmw.Firewall{
	// [required] url of the iprepd instance to use
	IPrepdURL: os.Getenv("IPREPD_HOST_URL"),
	
	// [required] auth string to authenticate against iprepd
	IPrepdAuthStr: os.Getenv("IPREPD_AUTH_STR"),
	
	// [required] reject any ip with reputation below a given score
	RejectBelowScore: 100,
	
	// optionally add IPs you wish to unconditionally allow
	Whitelist: []net.IP{},
	
	// optionally log all dropped http requests
	LogBlocked: true,
	
	// optionally allow any request if there was a problem reaching iprepd
	FailOpen: false,
	
	// optionally use non-default http client settings
	HTTPClient: &http.Client{Timeout: time.Second * 10},
}
```

* Wrap your [http.Handler](https://golang.org/pkg/net/http/#Handler) with the [Wrap()](https://godoc.org/github.com/adrianosela/iprepd-firewall/fwmw#Firewall.Wrap) method. The returned http.Handler will only serve requests from IPs which are either whitelisted or have a reputation above the given RejectBelowScore in iprepd.

```
h := yourHandler()
hProtected := fw.Wrap(h)

err := http.ListenAndServe(":8080", hProtected)
if err != nil {
	// handle listen and serve error
}
```
