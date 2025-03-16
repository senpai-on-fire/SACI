import { rest } from 'msw'

// Simplest mock data
const mockData = {
  // TODO: replace
}

export const handlers = [
  rest.get('/api/blueprints', (_, res, ctx) => {
    return res(ctx.json(mockData))
  }),
]