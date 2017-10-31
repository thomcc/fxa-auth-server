/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

const errors = require('../error')
const isA = require('joi')
const validators = require('./validators')
const HEX_STRING = validators.HEX_STRING

module.exports = (log, db, customs) => {
  return [
    {
      method: 'POST',
      path: '/tokenCodes/verify',
      config: {
        validate: {
          payload: {
            uid: isA.string().max(32).regex(HEX_STRING).required(),
            code: isA.string().required() // code length is configurable, don't set min/max
          }
        }
      },
      handler (request, reply) {
        log.begin('tokenCodes.verify', request)

        const uid = request.payload.uid
        const code = request.payload.code.toUpperCase()

        customs.checkIpOnly(request, 'tokenCodes')
          .then(verifyCode)
          .then(emitMetrics)
          .then(reply, reply)

        function verifyCode() {
          return db.verifyTokenCode(code, {uid: uid})
            .then(() => {}, (err) => {
              if (err.errno === errors.ERRNO.EXPIRED_TOKEN_VERIFICATION_CODE) {
                log.error({
                  op: 'account.token.code.expired',
                  uid: uid,
                  err: err
                })
              }
              throw err
            })
        }

        function emitMetrics() {
          log.info({
            op: 'account.token.code.verified',
            uid: uid
          })

          return request.emitMetricsEvent('tokenCodes.verified', {uid: uid})
            .then(() => ({}))
        }
      }
    }
  ]
}

