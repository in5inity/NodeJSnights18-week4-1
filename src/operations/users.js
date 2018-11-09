'use strict'

const log = require('../utils/logger')
const userRepository = require('../repositories/users')
const errors = require('../utils/errors')
const crypto = require('../utils/crypto')

async function signUp(input) {
  log.info('user signUp')

  const user = {
    name: input.name,
    email: input.email.toLowerCase(),
    password: await crypto.hashPassword(input.password),
    disabled: false,
  }

  // do we have this user already?
  const alreadyExists = await userRepository.findByEmail(user.email)
  if (alreadyExists) {
    throw new errors.ConflictError('User already exists.')
  }

  const newUser = await userRepository.create(user)
  newUser.setAccessToken = await crypto.generateAccessToken(newUser.id)
  log.info('Finished signUp successfully.')
  return newUser
}

async function signIn(input) {
  log.info('user signIn')

  const user = {
    email: input.email.toLowerCase(),
    password: input.password,
  }

  const existingUser = await userRepository.findByEmail(user.email)
  if (!existingUser) {
    // Consider not exposing that user doesn't exist, just say authorization failed
    throw new errors.UnauthorizedError('User does not exist.')
  }

  // compare password
  const matches = await crypto.comparePasswords(user.password, existingUser.password)

  if (!matches) {
    // Consider not exposing password mismatch, just say authorization failed
    throw new errors.UnauthorizedError('Bad password.')
  }

  // Check if user login isn't disabled at the moment
  if (existingUser.disabled) {
    throw new errors.UnauthorizedError()
  }

  existingUser.setAccessToken = await crypto.generateAccessToken(existingUser.id)

  // Never return the password hash to client
  delete existingUser.password

  log.info('User signed in.')

  return existingUser
}

async function verifyTokenPayload(input) {
  // never do in production
  log.info({ input }, 'verifyTokenPayload')
  const jwtPayload = await crypto.verifyAccessToken(input.jwtToken)
  const now = Date.now()
  if (!jwtPayload || !jwtPayload.exp || now >= jwtPayload.exp * 1000) {
    throw new errors.UnauthorizedError()
  }

  const userId = parseInt(jwtPayload.userId)
  const user = userRepository.findById(userId)

  if (!user || user.disabled) {
    throw new errors.UnauthorizedError()
  }

  log.info('verifyTokenPayload')
  return {
    user,
    loginTimeout: jwtPayload.exp * 1000,
  }
}


module.exports = {
  signUp,
  signIn,
  verifyTokenPayload,
}
