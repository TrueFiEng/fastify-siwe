# fastify-siwe

[Sign In with Ethereum](https://login.xyz) plugin for [Fastify](https://fastify.io).

## Example

See [packages/example](./packages/example) to see an example of the usage.

## How it works

![diagram](./packages/fastify-siwe/images/sequence.drawio.svg)

1. The frontend requests a nonce from the backend server. The nonce must be generated and verified on the backend to protect against replay attacks.
2. Backend server initializes empty session with the nonce.
3. The dapp signs the message with user's wallet and sends the signed message to the backend server.
4. Backend server updates previous initialized session by adding the message to it. In the response backend sets HttpOnly and secure cookie with token that is simply the signed message.
5. The cookie with token is included in every request that has an option `credentials: 'include'`.

Default routes enabling this flow can be added to the fastify app using the `registerSiweRoutes` method.

Example of the signed message:

```json
{
  "signature": "0xafa5d63362c63b0da57f152afb0fbd296abd1aec046355927f2c34e26ab67b1a58ce34bcd609d312293391005c25780a87c110cfb6374a747184a35b047b08d91c",
  "message": {
    "domain": "localhost:3002",
    "address": "0x2C6e1d8a2E457c5D79fAD2c9F2f0f463e0Df5376",
    "statement": "Sign in with Ethereum to the app.",
    "uri": "http://localhost:3002",
    "version": "1",
    "chainId": 1,
    "nonce": "JGiZrkbZ2uwUXl5yl",
    "issuedAt": "2022-04-23T17:25:20.427Z"
  }
}
```

## Installation

```
npm add fastify-siwe

yarn add fastify-siwe

pnpm add fastify-siwe
```

## Usage

Register the middleware:

```typescript
import { signInWithEthereum, registerSiweRoutes } from 'fastify-siwe'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'

void fastify.register(cors, {
  credentials: true,
  origin: true,
})
fastify.register(cookie)
fastify.register(signInWithEthereum())
registerSiweRoutes(fastify)
```

All requests come decorated with `req.siwe` object.
`req.siwe.session` will contain be present if the request is authenticated.

```typescript
fastify.get('/siwe/me', {}, async function handler(this: FastifyInstance, req: FastifyRequest, reply) {
  if (!req.siwe.session) {
    return reply.status(401).send()
  }

  console.log('address =', req.siwe.session.address)
})
```

Generating a new nonce:

```typescript
const nonce = await req.siwe.generateNonce()
```

> Checkout the full example at `packages/example`

### Implementing a custom store

By default, sessions are stored in memory. Session data will be lost on server restart.

To preserve sessions you can implement a custom store backed by a database.

```typescript
import { SessionStore, signInWithEthereum } from 'fastify-siwe'

class MyStore implements SessionStore {
  async get(nonce: string): Promise<StoredSession | undefined> {
    // Fetch from database
  }

  public async save(session: StoredSession) {
    // Save to database
  }

  async remove(nonce: string): Promise<void> {
    // Delete from database
  }
}

fastify.register(signInWithEthereum({ store: new MyStore() }))
```
