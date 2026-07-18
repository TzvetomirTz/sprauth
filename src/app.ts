import express from 'express';
import challengeRouter from './routes/challenge.route.js';
import cors from 'cors';
import secRouter from './routes/sec.route.js';
import authRouter from './routes/auth.route.js';
import sessionRouter from './routes/session.route.js';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: 'http://localhost:5173'
}));

app.use('/sec/', secRouter);
app.use('/challenge/', challengeRouter);
app.use('/auth/', authRouter);
app.use('/session/', sessionRouter);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
