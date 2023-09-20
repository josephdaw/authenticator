const jwt = require('jsonwebtoken');
// const request = require('supertest');

const authMiddleware = require('./index');

describe.skip('authMiddleware', () => {
  let req, res, next;

  beforeEach(() => {
    req = {
      headers: {},
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    next = jest.fn();
  });

  it('should call next if x-api-key header is valid', () => {
    req.headers['x-api-key'] = process.env.API_KEY;

    authMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('should return 401 error if x-api-key header is invalid', () => {
    req.headers['x-api-key'] = 'invalid-key';

    authMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid API key' });
  });

  it('should call next if Authorization header is valid', () => {
    const token = jwt.sign({ username: 'testuser' }, process.env.JWT_SECRET);
    req.headers.authorization = `Bearer ${token}`;

    authMiddleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user.username).toBe('testuser');
  });

  it('should return 401 error if Authorization header is missing', () => {
    authMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Token missing' });
  });

  it('should return 401 error if JWT token is invalid', () => {
    const token = jwt.sign({ username: 'testuser' }, 'wrong-secret');
    req.headers.authorization = `Bearer ${token}`;

    authMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid token' });
  });
});

// old tests
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