package pop3_server

import (
	"crypto/rand"
	"crypto/tls"
	"github.com/Jinnrry/gopop"
	"github.com/Jinnrry/pmail/config"
	log "github.com/sirupsen/logrus"
	"time"
)

var instance *gopop.Server
var instanceTls *gopop.Server

func StartWithTls() {
	crt, err := tls.LoadX509KeyPair(config.Instance.SSLPublicKeyPath, config.Instance.SSLPrivateKeyPath)
	if err != nil {
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert,
		Time:         time.Now,
		Rand:         rand.Reader,
	}
	instanceTls = gopop.NewPop3Server(995, "pop."+config.Instance.Domain, true, tlsConfig, action{})
	instanceTls.ConnectAliveTime = 5 * time.Minute

	log.Infof("POP3 With TLS Server Start On Port :995")

	err = instanceTls.Start()
	if err != nil {
		panic(err)
	}
}

func Start() {
	crt, err := tls.LoadX509KeyPair(config.Instance.SSLPublicKeyPath, config.Instance.SSLPrivateKeyPath)
	if err != nil {
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert,
		Time:         time.Now,
		Rand:         rand.Reader,
	}
	instance = gopop.NewPop3Server(110, "pop."+config.Instance.Domain, false, tlsConfig, action{})
	instance.ConnectAliveTime = 5 * time.Minute
	log.Infof("POP3 Server Start On Port :110")

	err = instance.Start()
	if err != nil {
		panic(err)
	}
}

func Stop() {
	if instance != nil {
		instance.Stop()
	}

	if instanceTls != nil {
		instanceTls.Stop()
	}
}
