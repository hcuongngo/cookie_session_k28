const http = require('http')
const url = require('url')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const moment = require('moment')

const salRound = 10;

const users = [
  { id: 1, email: "user1@gmail.com", password: bcrypt.hashSync("user1", salRound), role: "admin" },
  { id: 2, email: "user2@gmail.com", password: bcrypt.hashSync("user2", salRound), role: "user" },
]

const items = [
  { id: 1, name: 'item 1', description: 'item 1 description' },
  { id: 2, name: 'item 2', description: 'item 2 description' },
  { id: 3, name: 'item 3', description: 'item 3 description' },
  { id: 4, name: 'item 4', description: 'item 4 description' },
  { id: 5, name: 'item 5', description: 'item 5 description' },
  { id: 6, name: 'item 6', description: 'item 6 description' },
  { id: 7, name: 'item 7', description: 'item 7 description' },
  { id: 8, name: 'item 8', description: 'item 8 description' },
  { id: 9, name: 'item 9', description: 'item 9 description' },
  { id: 10, name: 'item 10', description: 'item 10 description' },
  { id: 11, name: 'item 11', description: 'item 11 description' },
  { id: 12, name: 'item 12', description: 'item 12 description' },
  { id: 13, name: 'item 13', description: 'item 13 description' },
]

const hashPassword = async (password) => {
  return await bcrypt.hash(password, salRound)
}

const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword)
}

const sessions = {}

const generateSessionId = () => {
  return crypto.randomBytes(16).toString('hex')
}

// auth
// register
const handleApiRegister = (req, res) => {
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })

  req.on("end", async () => {
    const params = JSON.parse(body)
    const { email, password } = params
    const newUser = { id: users.length + 1, email, password, role: "user" }
    newUser.password = await hashPassword(password)
    users.push(newUser)
    const cloneNewUser = { ...newUser }
    delete cloneNewUser.password
    res.writeHead(201, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Register success",
      data: cloneNewUser
    }))
  })
}

const handleApiLogin = (req, res) => {
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })

  req.on("end", async () => {
    const params = JSON.parse(body)
    const { email, password } = params
    const checkEmailUser = users.find(user => user.email === email)
    if (!checkEmailUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return
    }
    const checkPasswordUser = await comparePassword(password, checkEmailUser.password)
    if (!checkPasswordUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return
    }
    const existingSession = Object.values(sessions).find(session => session.email === email)
    // time call login + period (60*60*1000)
    // 21:19 - 7 = 14:23 15:23
    const expireTime = moment(Date.now() + 3600000).unix()
    console.log("expireTime", expireTime)
    console.log("typeof expireTime", typeof expireTime)
    if (existingSession) {
      for (const sessionId in sessions) {
        const session = sessions[sessionId]
        if (session.email === email) {
          res.setHeader('Set-Cookie', `sessionId=${sessionId}; Expires=${expireTime}`)
        }
      }
    } else {
      const sessionId = generateSessionId()
      console.log({ sessionId })
      sessions[sessionId] = checkEmailUser
      res.setHeader('Set-Cookie', `sessionId=${sessionId}; Expires=${expireTime}`)
    }
    const cloneNewUser = { ...checkEmailUser }
    delete cloneNewUser.password
    res.writeHead(200, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Login Success",
      data: cloneNewUser
    }))
  })
}


const handleApiChangePassword = (req, res) => {
  let body = ""
  req.on("data", (chunk) => {
    body += chunk.toString()
  })
  req.on("end", async () => {
    const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("sessionId=")).split("=")[1]
    console.log({ sessionId })
    const expiredTime = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("Expires=")).split("=")[1]
    console.log({ expiredTime })
    if (!sessionId || !sessions[sessionId]) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return
    }
    if (parseInt(expiredTime) < moment().unix()) {
      delete sessions[sessionId]
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Cookie expired. Login again")
      return
    }
    const { email, password, newPassword } = JSON.parse(body)
    const checkEmailUser = users.find(user => user.email == email)
    if (!checkEmailUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return
    }
    const checkPasswordUser = await comparePassword(password, checkEmailUser.password)
    if (!checkPasswordUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return
    }
    const hashedNewPassword = await hashPassword(newPassword)
    checkEmailUser.password = hashedNewPassword
    sessions[sessionId].password = hashedNewPassword
    res.writeHead(200, {
      "Content-Type": "text/plain"
    })
    res.end("Change password success")
  })
}

const handleApiForgotPassword = (req, res) => {
  let body = ""
  req.on("data", (chunk) => {
    body += chunk.toString()
  })
  req.on("end", async () => {
    const { email, newPassword } = JSON.parse(body)
    const checkEmailUser = users.find(user => user.email === email)
    if (!checkEmailUser) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return
    }
    const hashedNewPassword = await hashPassword(newPassword)
    checkEmailUser.password = hashedNewPassword
    res.writeHead(200, {
      "Content-Type": "text/plain"
    })
    res.end("Reset password success")
  })
}

const handleApiLogout = (req, res) => {
  const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("sessionId=")).split("=")[1]
  if (!sessionId || !sessions[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return
  }
  delete sessions[sessionId]
  res.writeHead(200, {
    "Content-Type": "text/plain"
  })
  res.end("Logout")
}

const handleApiGetItems = (req, res) => {
  const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("sessionId=")).split("=")[1]
  const expiredTime = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("Expires=")).split("=")[1]
  if (!sessionId || !sessions[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return
  }
  if (parseInt(expiredTime) < moment().unix()) {
    delete sessions[sessionId]
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Cookie expired. Login again")
    return
  }
  res.writeHead(200, {
    "Content-Type": "application/json"
  })
  res.end(JSON.stringify({
    message: "Get items success",
    data: items
  }))
}

const handleApiGetItemById = (req, res) => {
  const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("sessionId=")).split("=")[1]
  if (!sessionId || !sessions[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return
  }
  const expiredTime = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("Expires=")).split("=")[1]
  if (parseInt(expiredTime) < moment().unix()) {
    delete sessions[sessionId]
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Cookie expired. Login again")
    return
  }
  const reqUrl = url.parse(req.url, true)
  const path = reqUrl.pathname
  const itemId = parseInt(path.split("/")[3])
  console.log({ itemId })
  const index = items.findIndex(item => item.id === itemId)
  if (index === -1) {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Item id not found")
    return
  }
  res.writeHead(200, {
    "Content-Type": "application/json"
  })
  res.end(JSON.stringify({
    message: "Get item detail success",
    data: items[index]
  }))

}

const handleApiGetItemsPagination = (req, res) => {
  const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("sessionId=")).split("=")[1]
  if (!sessionId || !sessions[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return
  }
  const expiredTime = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("Expires=")).split("=")[1]
  if (parseInt(expiredTime) < moment().unix()) {
    delete sessions[sessionId]
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Cookie expired. Login again")
    return
  }
  const reqUrl = url.parse(req.url, true)
  const path = reqUrl.pathname
  const pageIndex = reqUrl.query.pageIndex || 1
  const limit = reqUrl.query.limit || 10
  const startIndex = (pageIndex - 1) * limit
  const endIndex = startIndex + limit - 1
  let result = {
    data: items.slice(startIndex, endIndex + 1),
    itemPerPage: limit,
    totalPages: Math.ceil(items.length / limit),
    currentPage: pageIndex,
  }
  res.writeHead(200, {
    "Content-Type": "application/json"
  })
  res.end(JSON.stringify({
    message: "Get items pagination success",
    data: result
  }))
}

const handleApiCreateNewItem = (req, res) => {
  const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("sessionId=")).split("=")[1]
  if (!sessionId || !sessions[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return
  }
  const expiredTime = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("Expires=")).split("=")[1]
  if (parseInt(expiredTime) < moment().unix()) {
    delete sessions[sessionId]
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Cookie expired. Login again")
    return
  }
  if (sessions[sessionId].role !== "admin") {
    res.writeHead(403, {
      "Content-Type": "text/plain"
    })
    res.end("Forbidden")
    return
  }
  let body = "";
  req.on("data", (chunk) => {
    body += chunk.toString()
    console.log("body", body)
  })
  req.on("end", () => {
    let newItem = JSON.parse(body)
    console.log("newItem", newItem)
    const { name, description } = newItem
    if (!name) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Name is required")
      return
    }
    if (!description) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Description is required")
      return
    }
    newItem = { id: items.length + 1, ...newItem }
    items.push(newItem)
    res.writeHead(201, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Create new item success",
      data: newItem
    }))
  })
}

const handleApiUpdateItem = (req, res) => {
  const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("sessionId=")).split("=")[1]
  if (!sessionId && !sessions[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return
  }
  const expiredTime = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("Expires=")).split("=")[1]
  if (parseInt(expiredTime) < moment().unix()) {
    delete sessions[sessionId]
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Cookie expired. Login again")
    return
  }
  if (sessions[sessionId].role !== "admin") {
    res.writeHead(403, {
      "Content-Type": "text/plain"
    })
    res.end("Forbidden")
    return
  }
  const reqUrl = url.parse(req.url, true)
  const path = reqUrl.pathname
  const itemId = parseInt(path.split("/")[3])
  const checkItemIndex = items.findIndex(item => item.id === itemId)
  console.log("checkItemIndex", checkItemIndex)
  if (!checkItemIndex) {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Item not found")
    return
  }
  let body = ""
  req.on("data", (chunk) => {
    body += chunk.toString()
  })
  req.on("end", () => {
    let updateItem = JSON.parse(body)
    const { name, description } = updateItem
    if (!name) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Name is required")
      return
    }
    if (!description) {
      res.writeHead(400, {
        "Content-Type": "text/plain"
      })
      res.end("Description is required")
      return
    }
    items[checkItemIndex] = { ...items[checkItemIndex], ...updateItem }
    res.writeHead(200, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: "Update item success",
      data: items[checkItemIndex]
    }))
  })
}

const handleApiDeleteItem = (req, res) => {
  const sessionId = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("sessionId=")).split("=")[1]
  if(!sessionId || !sessions[sessionId]) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return
  }
  const expiredTime = req.headers.cookie && req.headers.cookie.split("; ").find(cookie => cookie.startsWith("Expires=")).split("=")[1]
}

const handleRequest = (req, res) => {
  const reqUrl = url.parse(req.url, true)
  const path = reqUrl.pathname
  const itemId = parseInt(path.split("/")[3])

  if (req.method === "POST" && path === "/api/auth/register") {
    handleApiRegister(req, res)
  } else if (req.method === "POST" && path === "/api/auth/login") {
    handleApiLogin(req, res)
  } else if (req.method === "PUT" && path === "/api/auth/change-password") {
    handleApiChangePassword(req, res)
  } else if (req.method === "PUT" && path === "/api/auth/forgot-password") {
    handleApiForgotPassword(req, res)
  } else if (req.method === "POST" && path === "/api/auth/logout") {
    handleApiLogout(req, res)
  } else if (req.method === "GET" && path === "/api/items") {
    handleApiGetItems(req, res)
  } else if (req.method === "GET" && path.startsWith("/api/items/") && itemId) {
    handleApiGetItemById(req, res)
  } else if (req.method === "GET" && path === "/api/items/pagination") {
    handleApiGetItemsPagination(req, res)
  } else if (req.method === "POST" && path === "/api/items") {
    handleApiCreateNewItem(req, res)
  } else if (req.method === "PUT" && path.startsWith("/api/items/") && itemId) {
    handleApiUpdateItem(req, res)
  }
  else {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Not found")
  }
}

const server = http.createServer(handleRequest)

const PORT = 3000
server.listen(PORT, () => {
  console.log(`Running in ${PORT}`)
})