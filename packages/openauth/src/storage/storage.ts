interface AuthorizationState {
  redirect_uri: string
  response_type: string
  state: string
  client_id: string
  audience?: string
  pkce?: PKCE
}

interface PKCE {
  challenge: string
  method: "S256"
}

interface CodeProperties {
  type: string
  properties: any
  redirectURI: string
  clientID: string
  pkce?: PKCE
}

interface OauthCode {
  type: string
  properties: any
  clientID: string
  redirectURI: string
  pkce?: PKCE
}

interface RefreshTokenProperties {
  type: string
  properties: any
  clientID: string
}

export interface StorageAdapter {
  getOauthCode(code: string): Promise<OauthCode>
  getRefreshToken(
    subject: string,
    refreshToken: string,
  ): Promise<RefreshTokenProperties>
  setAuthorizationCode(
    code: string,
    properties: CodeProperties,
    ttl: number,
  ): Promise<void>
  setRefreshToken(
    subject: string,
    refreshToken: string,
    properties: RefreshTokenProperties,
    ttl: number,
  ): Promise<void>
  invalidateOauthCode(code: string): Promise<void>
  invalidateKeys(subject: string): Promise<void>
}

function encode(key: string[]) {
  return key.map((k) => k.replaceAll(SEPERATOR, ""))
}

export interface KVStorageAdapter {
  get(key: string[]): Promise<Record<string, any> | undefined>
  remove(key: string[]): Promise<void>
  set(key: string[], value: any, expiry?: Date): Promise<void>
  scan(prefix: string[]): AsyncIterable<[string[], any]>
}

export function createKvStore(adapter: KVStorageAdapter): StorageAdapter {
  return {
    getOauthCode: (code) => {
      const key = ["oauth:code", code.toString()]
      return adapter.get(encode(key)) as Promise<CodeProperties>
    },
    getRefreshToken: (subject, refreshToken) => {
      const key = ["oauth:refresh", subject, refreshToken]
      return adapter.get(encode(key)) as Promise<RefreshTokenProperties>
    },
    setAuthorizationCode: (code, properties, ttl) => {
      const key = ["oauth:code", code]
      return adapter.set(encode(key), properties, ttl)
    },
    setRefreshToken: (subject, refreshToken, properties, ttl) => {
      const key = ["oauth:refresh", subject, refreshToken]
      return adapter.set(encode(key), properties, ttl)
    },
    invalidateOauthCode: (code) => {
      const key = ["oauth:code", code.toString()]
      return adapter.remove(encode(key))
    },
    invalidateKeys: async (subject) => {
      for await (const [key] of adapter.scan(["oauth:refresh", subject])) {
        await adapter.remove(key)
      }
    },
  }
}

const SEPERATOR = String.fromCharCode(0x1f)

export function joinKey(key: string[]) {
  return key.join(SEPERATOR)
}

export function splitKey(key: string) {
  return key.split(SEPERATOR)
}
