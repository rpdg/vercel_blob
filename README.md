# Go Vercel Blob Client

This is a Golang package that has been transcribed from [vercel_blob](https://github.com/lancedb/vercel_blob), aiming to provide similar functionality and features.

I personally extend sincere thanks and appreciation to the original author for their Rust package, which has served as a valuable foundation. If you are interested in the original author's Rust package, please visit the following link: [https://github.com/lancedb/vercel_blob](https://github.com/lancedb/vercel_blob)



## Authentication

### Within your application

If your golang code is part of a golang serverless function then authentication is automatic
and provided as a part of the vercel runtime.

### Outside your application

If your golang code is part of a client package (running in the browser via wasm or running
some kind of custom client application) then you will need to obtain an authentication
token. This can be done by creating a route in your server that will supply short-lived
authentication tokens to authorized users.  

