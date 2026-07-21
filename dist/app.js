import express from 'express';
import challengeRouter from './routes/challenge.route.js';
import cors from 'cors';
import secRouter from './routes/sec.route.js';
import sessionRouter from './routes/session.route.js';
import adminRouter from './routes/admin.route.js';
import { pathToFileURL } from 'node:url';
const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors({
    origin: 'http://localhost:5173'
}));
app.use('/sec/', secRouter);
app.use('/challenge/', challengeRouter);
app.use('/session/', sessionRouter);
app.use('/admin/', adminRouter);
// Only start listening when this module is the process entrypoint (npm start / dev).
// When imported by tests (Supertest binds its own ephemeral port), skip listening.
const isEntrypoint = process.argv[1] !== undefined &&
    import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntrypoint) {
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}
export default app;
//# sourceMappingURL=app.js.map