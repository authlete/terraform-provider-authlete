# Negative cases

Each directory holds a configuration that **must fail**, and an `expect` file
holding a regular expression the failure has to match.

A fix that makes something impossible cannot be proven by a clean plan. It is
proven by the attempt being refused, with a message that says why. These check
both halves: that it is refused, and that the message is the useful one rather
than a bare 401 or a schema error from somewhere else.

```
./run.sh negative
```

Runs every case. No credentials needed; none of them reach the API.
