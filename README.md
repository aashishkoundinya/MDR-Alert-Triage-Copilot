Terminal 1:
```bash
cd backend
uvicorn main:app --reload --port 8000
```

Terminal 2:
```bash
cd my-app
npm run dev
```

Terminal 3:
```bash
cd log_generator
python log_generator_local.py
```