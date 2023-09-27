const express = require('express')
const mongoose = require('require')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { expressjwt: expressJwt } = require('express-jwt')
const User = require('./User')

// ! put url
mongoose.connect('')

const app = express()
const port = 3000

app.use(express.json())

// environment variable
const validateJwt = expressJwt({ secret: process.env.SECRET, algorithms: ['HS256'] })

const signedToken = _id => jwt.sign({ _id }, process.env.SECRET)

// register
app.post('/register', async (req, res) => {
  const { body } = req
  console.log({ body })
  try {
    const isUser = await User.findOne({ email: body.email })
    if (isUser) {
      return res.status(403).send('User already exists')
    }
    const salt = await bcrypt.genSalt()
    const hashed = await bcrypt.hash(body.password, salt)
    const user = await User.create({ email: body.email, password: hashed, salt })
    const signed = signedToken(user._id)
    // res.send({ _id: user._id })
    res.status(201).send(signed)
  } catch (err) {
    console.log(err)
    res.status(500).send(err.message)
  }
})

// Login
app.post('/login', async (req, res) => {
  const { body } = req
  try {
    const user = await User.findOne({ email: body.email })
    if (!user) {
      res.status(403).send('invalid username and/or password')
    } else {
      const isMatch = await bcrypt.compare(body.password, user.password)
      if (isMatch) {
        const signed = signedToken(user._id)
        res.status(200).send(signed)
      } else {
        res.status(403).send('invalid username and/or password')
      }
    }
  } catch(err) {
      res.status(500).send(err.message)
  }
})

const findAndAssignUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.auth._id)
    if (!user) {
      return res.status(401).end()
    }
    req.user = user
    next()
  } catch (e) {
    next(e)
  }
}

const isAuthenticated = express.Router().use(validateJwt, findAndAssignUser)

app.get('/lele', isAuthenticated, (req, res) => {
  throw new Error('New error')
  res.send(req.user)
})

app.use((err, req, res, next) => {
  console.error('My new error', err.stack)
  next(err)
})

app.use((err, req, res, next) => {
  res.send('An error has occurred')
})

app.listen(port, () => {
  console.log('Running the application')
})
