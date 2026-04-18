import express from 'express';
import authRouter from './routes/auth.route.js';

const app = express();
const PORT = process.env.PORT || 3000;

app.use('/auth/', authRouter);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
