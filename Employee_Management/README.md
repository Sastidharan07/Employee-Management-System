
# 👩‍💼 Employee Management System

![Node.js](https://img.shields.io/badge/Node.js-Express-green) 
![SQLite](https://img.shields.io/badge/Database-SQLite-lightblue)
![EJS](https://img.shields.io/badge/View-EJS-blueviolet)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

A complete role-based Employee Management System built with **Node.js**, **Express**, **SQLite**, and **EJS templates**. It allows administrators to manage employees, track attendance, and handle leave applications. Employees can mark attendance and apply for leave through a clean, responsive UI.

---

## ✨ Features

### 🔐 Authentication & Security
- Secure login system with **bcrypt password hashing**
- **Session-based authentication** using `express-session`
- **Role-based access control** (Admin / Employee)
- Admin-only user creation (no open registration)

### 🛠️ Admin Capabilities
- 📊 Admin dashboard with real-time statistics
- 👥 Manage employees (Add, View, Update, Delete)
- 🗂 Approve/Reject leave applications
- 🧾 View attendance & leave summaries

### 👨‍💼 Employee Capabilities
- 🖥 Personalized employee dashboard
- ✅ Daily attendance marking
- 📝 Leave application system
- 📅 View leave status and attendance history

---

## 🧰 Technology Stack

| Layer       | Tech                              |
|-------------|-----------------------------------|
| Frontend    | HTML, CSS, EJS                    |
| Backend     | Node.js, Express.js               |
| Database    | SQLite (file-based, free)         |
| Auth        | bcrypt, express-session           |

---

## 🚀 Getting Started

### 1. Clone & Install Dependencies

```bash
git clone https://github.com/yourusername/employee-management-system.git
cd employee-management-system
npm install
```

### 2. Run the App

```bash
npm start         # Production
npm run dev       # Development (nodemon auto-reload)
```

### 3. Access Locally

```text
http://localhost:3000
```

---

## 🔑 Default Credentials

> **Admin Login**
- Username: `admin`
- Password: `admin123`

---

## 🧱 Database Structure

| Table             | Description                         |
|------------------|-------------------------------------|
| `users`          | Stores admin and employee info      |
| `attendance`     | Stores daily attendance records     |
| `leave_applications` | Handles leave requests & status |

> ✅ The `database.db` file is **auto-created** on first run.

---

## 🌱 Sample Data

Run the seeder to populate employees:

```bash
node scripts/seed-database.js
```

**Sample Users:**
- `john.doe` / `password123`
- `jane.smith` / `password123`
- `mike.johnson` / `password123`

---

## 🧭 Workflow

### 👨‍💼 Admin
1. Login with admin credentials
2. Add employees
3. Approve/Reject leave requests
4. View statistics, attendance, and leave records

### 👩‍💼 Employee
1. Login with provided credentials
2. Mark attendance
3. Apply for leave
4. View status and history

---

## 📁 Project Structure

```
employee-management-system/
├── server.js
├── database.db
├── public/
│   └── styles.css
├── views/
│   ├── layout.ejs
│   ├── login.ejs
│   ├── admin/
│   │   ├── dashboard.ejs
│   │   ├── employees.ejs
│   │   ├── add-employee.ejs
│   │   └── leave-applications.ejs
│   └── user/
│       ├── dashboard.ejs
│       ├── attendance.ejs
│       └── leave.ejs
└── scripts/
    └── seed-database.js
```

---

## 🎨 Customization

- Modify styles in `public/styles.css`
- Add routes in `server.js` for new features
- Update EJS files in `views/` for layout/UI changes
- Use environment variables for config in production

---

## 🚢 Deployment Notes

For production deployment:
- Replace session secrets
- Use `cookie.secure: true` in HTTPS
- Use `pm2` or Docker for running the server
- Reverse proxy with **Nginx** or **Apache**
- Add environment variables for config

---

## 📜 License

MIT License — Free for personal and commercial use.

---

## 🙋 Need Help?

Feel free to [open an issue](https://github.com/yourusername/employee-management-system/issues) or reach out for improvements, bugs, or feature suggestions!
