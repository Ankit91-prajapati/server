import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import 'dotenv/config';
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";

const app = express();
const port = process.env.PORT || 3000;

connectDB();
app.use(express.json());
app.use(cookieParser());



const allowedOrigins = [
  
  "http://localhost:3000"
];

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"]
}));




app.get('/', (req, res) => {
  res.send("Backend API is running");
});

app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

app.listen(port, () => console.log(`Server started on port ${port}`));
