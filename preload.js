const { contextBridge, ipcRenderer } = require("electron")

contextBridge.exposeInMainWorld("kindeAuth", {
  login: () => ipcRenderer.invoke("auth:login"),
  getAccessToken: () => ipcRenderer.invoke("auth:getAccessToken"),
  logout: () => ipcRenderer.invoke("auth:logout"),
  getSession: () => ipcRenderer.invoke("auth:getSession"),
})