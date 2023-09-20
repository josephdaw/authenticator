const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../../src/app');

describe.skip('authMiddleware', () => {
    describe('given a request with an x-api-key header', () => {
        it('should return a 200 status and test message', async () => {
            const res = await request(app)
                .get('/api/protected')
                .set('x-api-key', process.env.API_KEY);
            expect(res.status).toBe(200);
            expect(res.body.message).toBe('you have reached the protected route');
        });
    });

    describe('given a request with an Authorization header', () => {
        it('should return a 200 status and test message', async () => {
            const token = jwt.sign({ username: 'testuser' }, process.env.JWT_SECRET);
            const res = await request(app)
                .get('/api/protected')
                .set('Authorization', `Bearer ${token}`);
            expect(res.status).toBe(200);
            expect(res.body.message).toBe('you have reached the protected route');
        });
    });

    describe('given a request without an Authorization header', () => {
        it('should return a 401 error and message to highlight header missing', async () => {
            const res = await request(app).get('/api/protected');
            expect(res.status).toBe(401);
            expect(res.body.error).toBe('Authorization header missing');
        });
    })

    describe('given a request with invalid credentials', () => {
        it('should return a 401 error for requests with an invalid API key', async () => {
            const res = await request(app)
                .get('/api/protected')
                .set('x-api-key', 'invalid-key');

            expect(res.status).toBe(401);
            expect(res.body.error).toBe('Invalid Credentials');
        });

        it('should return a 401 error for requests with an invalid JWT token', async () => {
            const token = jwt.sign({ username: 'testuser' }, 'wrong-secret');
            const res = await request(app)
                .get('/api/protected')
                .set('Authorization', `Bearer ${token}`);

            expect(res.status).toBe(401);
            expect(res.body.error).toBe('Invalid Credentials');
        });
    });
});