import React, { useEffect, useState } from 'react'
import AzureTerraformBuilder from './components/AzureTerraformBuilder'
import { Moon, Sun, Boxes } from 'lucide-react'

export default function App() {
  const [dark, setDark] = useState(false)
  useEffect(()=> {
    const cls = document.documentElement.classList
    dark ? cls.add('dark') : cls.remove('dark')
  }, [dark])

  return (
    <div className="min-h-screen text-slate-900 dark:text-slate-100">
      <header className="sticky top-0 z-20 bg-white/80 dark:bg-slate-900/80 backdrop-blur border-b">
        <div className="mx-auto max-w-7xl px-4 py-3 flex items-center gap-3">
          <Boxes className="h-6 w-6" />
          <h1 className="text-xl font-semibold">Azure Terraform Builder</h1>
          <div className="ml-auto flex items-center gap-2">
            <button className="btn btn-ghost" onClick={()=>setDark(d=>!d)}>
              {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              <span className="hidden sm:inline">{dark ? 'Light' : 'Dark'} mode</span>
            </button>
            <a className="btn" href="https://developer.hashicorp.com/terraform/docs" target="_blank">Terraform Docs</a>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl p-4 md:p-8">
        <AzureTerraformBuilder />
      </main>
      <footer className="border-t py-6 text-center text-xs text-slate-500">
        Built with Vite + React. This is a local-only tool—no data leaves your browser.
      </footer>
    </div>
  )
}
