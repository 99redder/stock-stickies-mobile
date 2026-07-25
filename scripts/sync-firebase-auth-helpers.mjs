import { mkdir, rm, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { loadEnv } from 'vite'

const projectId = 'red-s-stickies'
const sourceOrigin = `https://${projectId}.firebaseapp.com`
const htmlHelperNames = [
  'handler',
  'iframe',
  'links',
]
const scriptHelperNames = [
  'handler.js',
  'experiments.js',
  'iframe.js',
  'links.js',
]
const loadedEnv = loadEnv('production', process.cwd(), '')
const env = (name) => process.env[name] || loadedEnv[name] || ''
const authDirectory = resolve('public/__/auth')
const firebaseDirectory = resolve('public/__/firebase')

await rm(authDirectory, { recursive: true, force: true })
await mkdir(authDirectory, { recursive: true })
await mkdir(firebaseDirectory, { recursive: true })

await Promise.all(scriptHelperNames.map(async (name) => {
  const response = await fetch(`${sourceOrigin}/__/auth/${name}`)
  if (!response.ok) throw new Error(`Unable to download Firebase auth helper ${name}: ${response.status}`)
  await writeFile(resolve(authDirectory, name), Buffer.from(await response.arrayBuffer()))
}))

await Promise.all(htmlHelperNames.map(async (name) => {
  const response = await fetch(`${sourceOrigin}/__/auth/${name}`)
  if (!response.ok) throw new Error(`Unable to download Firebase auth helper ${name}: ${response.status}`)
  const html = (await response.text())
    .replaceAll('src="experiments.js"', 'src="/__/auth/experiments.js"')
    .replaceAll(`src="${name}.js"`, `src="/__/auth/${name}.js"`)
  const directory = resolve(authDirectory, name)
  await mkdir(directory, { recursive: true })
  await writeFile(resolve(directory, 'index.html'), html)
}))

await writeFile(resolve(firebaseDirectory, 'init.json'), JSON.stringify({
  apiKey: env('VITE_FIREBASE_API_KEY'),
  authDomain: 'mobile.stockstickies.com',
  projectId: env('VITE_FIREBASE_PROJECT_ID'),
  storageBucket: env('VITE_FIREBASE_STORAGE_BUCKET'),
  messagingSenderId: env('VITE_FIREBASE_MESSAGING_SENDER_ID'),
  appId: env('VITE_FIREBASE_APP_ID'),
}))
