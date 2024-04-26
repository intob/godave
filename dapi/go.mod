module github.com/intob/dave/dapi

go 1.22.1

require (
	github.com/intob/dave/godave v0.0.0
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20220411075957-e3b120b3f5fb // indirect
)

replace github.com/intob/dave/godave => ../godave
