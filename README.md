# please

> minimal implementation of `sudo` / `doas` in C


## why?

because the larger the codebase, the larger the attack surface, and this implementation is minimal so there's very little risk

also i wanted to make something useful in C


## compiling

```bash 
# compile
make
# set ownership to root and add setuid bit
sudo make install
```


## running

`./please <command> [args...]`


## contributing

as always, pull requests are welcome