import './App.css'
import { providers } from 'ethers'
import { SiweMessage } from 'siwe'
import { useEffect, useState } from 'react'

async function getNonce(): Promise<string> {
  const req = await fetch('http://localhost:3001/siwe/init', { method: 'POST' })
  const { nonce } = await req.json()
  return nonce
}

async function siweSignIn({ signature, message }: { signature: string; message: SiweMessage }): Promise<void> {
  await fetch('http://localhost:3001/siwe/signin', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      signature,
      message,
    }),
  })
}

async function checkAuthStatus({ chainId, address }: { chainId: number; address: string }): Promise<{
  message?: SiweMessage
}> {
  const url = new URL('http://localhost:3001/siwe/me')
  url.searchParams.append('chainId', chainId.toString())
  url.searchParams.append('address', address)
  const req = await fetch(url.toString(), {
    credentials: 'include',
  })
  return await req.json()
}

async function signOutRequest({ chainId, address }: { chainId: number; address: string }) {
  const url = new URL('http://localhost:3001/siwe/signout')
  url.searchParams.append('chainId', chainId.toString())
  url.searchParams.append('address', address)
  await fetch(url.toString(), {
    method: 'POST',
    credentials: 'include',
  })
}

function App() {
  const provider = new providers.Web3Provider((window as any).ethereum)
  const signer = provider.getSigner()

  const [message, setMessage] = useState<SiweMessage | undefined>()

  async function signIn() {
    // Prompt user for account connections
    await provider.send('eth_requestAccounts', [])

    const domain = window.location.host
    const origin = window.location.origin
    const statement = 'Sign in with Ethereum to the app.'

    const message = new SiweMessage({
      domain,
      address: await signer.getAddress(),
      statement,
      uri: origin,
      version: '1',
      chainId: await signer.getChainId(),
      nonce: await getNonce(),
    })

    const signature = await signer.signMessage(message.prepareMessage())

    await siweSignIn({ signature, message })

    const [chainId, address] = await Promise.all([signer.getChainId(), signer.getAddress()])

    void checkAuthStatus({ chainId, address }).then((res) => setMessage(res?.message))
  }

  async function signOut() {
    const [chainId, address] = await Promise.all([signer.getChainId(), signer.getAddress()])
    await signOutRequest({ chainId, address })
    setMessage(undefined)
  }

  useEffect(() => {
    const checkAuth = async () => {
      const [chainId, address] = await Promise.all([signer.getChainId(), signer.getAddress()])
      const res = await checkAuthStatus({ chainId, address })
      setMessage(res.message)
    }
    void checkAuth()
  }, [])

  return (
    <div className="App">
      <button onClick={signIn}>{!message ? 'Sign in' : 'Sign in again'}</button>
      <button disabled={!message} onClick={signOut}>
        Sign out
      </button>
      {message ? (
        <>
          <p>Logged in with {message.address}</p>
          <p>Chain ID: {message.chainId}</p>
          <p>Nonce: {message.nonce}</p>
          <p>IssuedAt: {message.issuedAt}</p>
        </>
      ) : (
        <p>Not logged in :(</p>
      )}
    </div>
  )
}

export default App
