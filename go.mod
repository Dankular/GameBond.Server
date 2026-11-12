module github.com/Dankular/GameBond.Server

go 1.25.0

require golang.org/x/crypto v0.45.0

require golang.org/x/sys v0.41.0

require (
	github.com/ebitengine/purego v0.9.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/shirou/gopsutil/v4 v4.25.12 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
)

require github.com/Dankular/GameBond.Core v0.1.0

replace github.com/Dankular/GameBond.Core => ../GameBond.Core
