module github.com/intob/dave/daved

go 1.22.1

require github.com/intob/dave/godave v0.0.0

require github.com/intob/dave/dapi v0.0.0

require (
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/intob/jfmt v0.2.2
	github.com/seiflotfy/cuckoofilter v0.0.0-20220411075957-e3b120b3f5fb // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

replace github.com/intob/dave/godave => ../godave

replace github.com/intob/dave/dapi => ../dapi
