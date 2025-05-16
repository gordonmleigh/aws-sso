package main

import "strings"

type Environment []string

func (env *Environment) Get(key string) string {
	for _, item := range *env {
		if strings.HasPrefix(item, key+"=") {
			return item[len(key)+1:]
		}
	}
	return ""
}

func (env *Environment) Set(key string, value string) {
	env.Unset(key)
	*env = append(*env, key+"="+value)
}

func (env *Environment) Unset(key string) {
	length := len(*env)
	cut := 0

	//ignore modernize: range is only evaluated once, here upper limit changes
	for i := 0; i < length-cut; i++ {
		if strings.HasPrefix((*env)[i], key+"=") {
			cut++
			if i < length-cut {
				(*env)[i] = (*env)[length-cut]
			}
		}
	}
	*env = (*env)[:length-cut]
}
