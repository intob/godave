module github.com/intob/dave

go 1.22.1


require (
    github.com/intob/dave/dapi v0.0.0
    github.com/intob/dave/godave v0.0.0
)

replace (
    github.com/intob/dave/dapi => ./dapi
    github.com/intob/dave/godave => ./godave
)