package set3

import (
    "fmt"
    "mtsn"
)

func Challenge21() {
 	generator := mtsn.Generator(1234)
 	value := generator.Extract()
 	fmt.Printf("Challenge 21: First random number %d\n", value)
 }
