const express = require("express")
const session = require("express-session")
const bcrypt = require("bcrypt")
const sqlite3 = require("sqlite3").verbose()
const path = require("path")
const multer = require("multer")
const fs = require("fs")

const app = express()
const PORT = process.env.PORT || 3000

// Database setup
const db = new sqlite3.Database("./database.db")

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, "public", "uploads", "profiles")
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true })
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir)
  },
  filename: (req, file, cb) => {
    // Generate unique filename with timestamp
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9)
    cb(null, "profile-" + uniqueSuffix + path.extname(file.originalname))
  },
})

const fileFilter = (req, file, cb) => {
  // Check if file is an image
  if (file.mimetype.startsWith("image/")) {
    cb(null, true)
  } else {
    cb(new Error("Only image files are allowed!"), false)
  }
}

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
})

// Middleware
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(express.static("public"))
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"))

// Session configuration
app.use(
  session({
    secret: "your-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to true in production with HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  }),
)

// Initialize database tables
function initializeDatabase() {
  // Users table - Updated to include profile_image
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    name TEXT NOT NULL,
    email TEXT,
    department TEXT,
    profile_image TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`)

  // Attendance table
  db.run(`CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date DATE NOT NULL,
    status TEXT NOT NULL DEFAULT 'present',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE(user_id, date)
  )`)

  // Enhanced leave applications table with absence tracking
  db.run(`CREATE TABLE IF NOT EXISTS leave_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    absence_status TEXT DEFAULT NULL,
    admin_comment TEXT,
    actual_return_date DATE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`)

  // Add employee status tracking table
  db.run(`CREATE TABLE IF NOT EXISTS employee_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'available',
    current_leave_id INTEGER,
    status_start_date DATE,
    status_end_date DATE,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (current_leave_id) REFERENCES leave_applications (id),
    UNIQUE(user_id)
  )`)

  // Create default admin user
  const adminPassword = bcrypt.hashSync("admin123", 10)
  db.run(
    `INSERT OR IGNORE INTO users (username, password, role, name, email, department) 
          VALUES (?, ?, ?, ?, ?, ?)`,
    ["admin", adminPassword, "admin", "System Administrator", "admin@company.com", "IT"],
  )
}

// Helper function to update employee status
function updateEmployeeStatus(userId, callback) {
  const today = new Date().toISOString().split("T")[0]

  // Check current leave status
  db.get(
    `SELECT * FROM leave_applications 
     WHERE user_id = ? 
     AND status = 'approved' 
     AND date('now') BETWEEN start_date AND end_date
     AND (absence_status = 'on-leave' OR absence_status IS NULL)
     ORDER BY created_at DESC LIMIT 1`,
    [userId],
    (err, currentLeave) => {
      if (err) {
        console.error("Error checking current leave:", err)
        return callback && callback()
      }

      let status = "available"
      let currentLeaveId = null
      let statusStartDate = null
      let statusEndDate = null

      if (currentLeave) {
        status = "on-leave"
        currentLeaveId = currentLeave.id
        statusStartDate = currentLeave.start_date
        statusEndDate = currentLeave.end_date
      }

      // Update or insert employee status
      db.run(
        `INSERT OR REPLACE INTO employee_status 
         (user_id, status, current_leave_id, status_start_date, status_end_date, updated_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))`,
        [userId, status, currentLeaveId, statusStartDate, statusEndDate],
        (err) => {
          if (err) {
            console.error("Error updating employee status:", err)
          }
          callback && callback()
        },
      )
    },
  )
}

// Function to check and update all employee statuses
function updateAllEmployeeStatuses() {
  console.log("Updating all employee statuses...")

  // Mark leaves as 'on-leave' if they've started
  db.run(
    `UPDATE leave_applications 
     SET absence_status = 'on-leave', updated_at = datetime('now')
     WHERE status = 'approved' 
     AND (absence_status IS NULL OR absence_status = '')
     AND date('now') BETWEEN start_date AND end_date`,
    (err) => {
      if (err) {
        console.error("Error updating absence status:", err)
      }
    },
  )

  // Update all employee statuses
  db.all('SELECT id FROM users WHERE role = "user"', (err, users) => {
    if (err) {
      console.error("Error fetching users for status update:", err)
      return
    }

    users.forEach((user) => {
      updateEmployeeStatus(user.id)
    })
  })
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (req.session.userId) {
    next()
  } else {
    res.redirect("/login")
  }
}

function requireAdmin(req, res, next) {
  if (req.session.userId && req.session.role === "admin") {
    next()
  } else {
    res.status(403).render("error", {
      message: "Access denied. Admin privileges required.",
      user: req.session.userId ? { role: req.session.role } : null,
    })
  }
}

// Routes
app.get("/", (req, res) => {
  if (req.session.userId) {
    if (req.session.role === "admin") {
      res.redirect("/admin/dashboard")
    } else {
      res.redirect("/user/dashboard")
    }
  } else {
    res.redirect("/login")
  }
})

app.get("/login", (req, res) => {
  if (req.session.userId) {
    res.redirect("/")
  } else {
    res.render("login", { error: null })
  }
})

app.post("/login", (req, res) => {
  const { username, password } = req.body

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      return res.render("login", { error: "Database error" })
    }

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.render("login", { error: "Invalid username or password" })
    }

    req.session.userId = user.id
    req.session.username = user.username
    req.session.role = user.role
    req.session.name = user.name

    if (user.role === "admin") {
      res.redirect("/admin/dashboard")
    } else {
      res.redirect("/user/dashboard")
    }
  })
})

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err)
    }
    res.redirect("/login")
  })
})

// Admin Routes
app.get("/admin/dashboard", requireAuth, requireAdmin, (req, res) => {
  // Get enhanced statistics including current absentees
  db.all(
    `
    SELECT 
      (SELECT COUNT(*) FROM users WHERE role = 'user') as total_employees,
      (SELECT COUNT(*) FROM leave_applications WHERE status = 'pending') as pending_leaves,
      (SELECT COUNT(*) FROM attendance WHERE date = date('now')) as today_attendance,
      (SELECT COUNT(*) FROM leave_applications 
       WHERE status = 'approved' 
       AND date('now') BETWEEN start_date AND end_date
       AND (absence_status = 'on-leave' OR absence_status IS NULL)) as current_absentees,
      (SELECT COUNT(*) FROM employee_status WHERE status = 'on-leave') as employees_on_leave
  `,
    (err, stats) => {
      if (err) {
        console.error("Dashboard stats error:", err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      // Get current absentees details
      db.all(
        `SELECT la.*, u.name as employee_name, u.department
         FROM leave_applications la
         JOIN users u ON la.user_id = u.id
         WHERE la.status = 'approved' 
         AND date('now') BETWEEN la.start_date AND la.end_date
         AND (la.absence_status = 'on-leave' OR la.absence_status IS NULL)
         ORDER BY la.end_date ASC`,
        (err, currentAbsentees) => {
          if (err) {
            console.error("Current absentees error:", err)
            currentAbsentees = []
          }

          res.render("admin/dashboard", {
            user: req.session,
            stats: stats[0] || {
              total_employees: 0,
              pending_leaves: 0,
              today_attendance: 0,
              current_absentees: 0,
              employees_on_leave: 0,
            },
            currentAbsentees: currentAbsentees || [],
          })
        },
      )
    },
  )
})

app.get("/admin/employees", requireAuth, requireAdmin, (req, res) => {
  db.all(
    `SELECT u.id, u.username, u.name, u.email, u.department, u.profile_image, u.created_at,
            es.status as employee_status, es.status_end_date as leave_end_date
     FROM users u
     LEFT JOIN employee_status es ON u.id = es.user_id
     WHERE u.role = "user"
     ORDER BY u.name`,
    (err, employees) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      res.render("admin/employees", { user: req.session, employees })
    },
  )
})

app.get("/admin/add-employee", requireAuth, requireAdmin, (req, res) => {
  res.render("admin/add-employee", { user: req.session, error: null })
})

app.post("/admin/add-employee", requireAuth, requireAdmin, upload.single("profileImage"), (req, res) => {
  const { username, password, name, email, department } = req.body

  if (!username || !password || !name) {
    // Delete uploaded file if validation fails
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting file:", err)
      })
    }
    return res.render("admin/add-employee", {
      user: req.session,
      error: "Username, password, and name are required",
    })
  }

  const hashedPassword = bcrypt.hashSync(password, 10)
  const profileImage = req.file ? req.file.filename : null

  db.run(
    "INSERT INTO users (username, password, name, email, department, profile_image, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [username, hashedPassword, name, email, department, profileImage, "user"],
    (err) => {
      if (err) {
        // Delete uploaded file if database insertion fails
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }

        if (err.code === "SQLITE_CONSTRAINT") {
          return res.render("admin/add-employee", {
            user: req.session,
            error: "Username already exists",
          })
        }
        console.error(err)
        return res.render("admin/add-employee", {
          user: req.session,
          error: "Database error",
        })
      }

      res.redirect("/admin/employees")
    },
  )
})

app.get("/admin/leave-applications", requireAuth, requireAdmin, (req, res) => {
  db.all(
    `
    SELECT la.*, u.name as employee_name 
    FROM leave_applications la 
    JOIN users u ON la.user_id = u.id 
    ORDER BY la.created_at DESC
  `,
    (err, applications) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      res.render("admin/leave-applications", { user: req.session, applications })
    },
  )
})

app.post("/admin/leave-action", requireAuth, requireAdmin, (req, res) => {
  const { applicationId, action, comment } = req.body

  if (action === "approved") {
    // Check for overlapping approved leaves before approving
    db.get("SELECT * FROM leave_applications WHERE id = ?", [applicationId], (err, application) => {
      if (err || !application) {
        console.error("Error fetching application:", err)
        return res.redirect("/admin/leave-applications?error=Application not found")
      }

      // Check for conflicts with other approved leaves
      db.get(
        `SELECT la.*, u.name as employee_name 
         FROM leave_applications la
         JOIN users u ON la.user_id = u.id
         WHERE la.user_id = ? 
         AND la.id != ?
         AND la.status = 'approved'
         AND ((la.start_date <= ? AND la.end_date >= ?) 
              OR (la.start_date <= ? AND la.end_date >= ?)
              OR (? <= la.start_date AND ? >= la.end_date))`,
        [
          application.user_id,
          applicationId,
          application.start_date,
          application.start_date,
          application.end_date,
          application.end_date,
          application.start_date,
          application.end_date,
        ],
        (err, conflict) => {
          if (err) {
            console.error("Conflict check error:", err)
            return res.redirect("/admin/leave-applications?error=Database error")
          }

          if (conflict) {
            return res.redirect(
              `/admin/leave-applications?error=Cannot approve: Employee already has approved leave from ${new Date(conflict.start_date).toLocaleDateString()} to ${new Date(conflict.end_date).toLocaleDateString()}`,
            )
          }

          // No conflicts, proceed with approval
          let absenceStatus = null
          const today = new Date()
          const startDate = new Date(application.start_date)
          const endDate = new Date(application.end_date)

          if (today >= startDate && today <= endDate) {
            absenceStatus = "on-leave"
          }

          db.run(
            "UPDATE leave_applications SET status = ?, admin_comment = ?, absence_status = ?, updated_at = datetime('now') WHERE id = ?",
            [action, comment || null, absenceStatus, applicationId],
            (err) => {
              if (err) {
                console.error("Error updating leave application:", err)
                return res.redirect("/admin/leave-applications?error=Failed to update application")
              }

              // Update employee status
              updateEmployeeStatus(application.user_id, () => {
                res.redirect("/admin/leave-applications?success=Leave application approved successfully")
              })
            },
          )
        },
      )
    })
  } else {
    // Handle rejection
    db.run(
      "UPDATE leave_applications SET status = ?, admin_comment = ?, updated_at = datetime('now') WHERE id = ?",
      [action, comment || null, applicationId],
      (err) => {
        if (err) {
          console.error("Error updating leave application:", err)
        }
        res.redirect("/admin/leave-applications")
      },
    )
  }
})

// Edit Employee Route
app.get("/admin/edit-employee/:id", requireAuth, requireAdmin, (req, res) => {
  const employeeId = req.params.id

  db.get(
    'SELECT id, username, name, email, department, profile_image FROM users WHERE id = ? AND role = "user"',
    [employeeId],
    (err, employee) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      if (!employee) {
        return res.render("error", { message: "Employee not found", user: req.session })
      }

      res.render("admin/edit-employee", { user: req.session, employee, error: null })
    },
  )
})

// Update Employee Route
app.post("/admin/edit-employee/:id", requireAuth, requireAdmin, upload.single("profileImage"), (req, res) => {
  const employeeId = req.params.id
  const { username, name, email, department, password, removeImage } = req.body

  if (!username || !name) {
    // Delete uploaded file if validation fails
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting file:", err)
      })
    }
    return db.get(
      'SELECT id, username, name, email, department, profile_image FROM users WHERE id = ? AND role = "user"',
      [employeeId],
      (err, employee) => {
        if (err || !employee) {
          return res.render("error", { message: "Employee not found", user: req.session })
        }
        res.render("admin/edit-employee", {
          user: req.session,
          employee,
          error: "Username and name are required",
        })
      },
    )
  }

  // Get current employee data to handle image updates
  db.get('SELECT profile_image FROM users WHERE id = ? AND role = "user"', [employeeId], (err, currentEmployee) => {
    if (err || !currentEmployee) {
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting file:", err)
        })
      }
      return res.render("error", { message: "Employee not found", user: req.session })
    }

    // Build update query
    let updateQuery = "UPDATE users SET username = ?, name = ?, email = ?, department = ?"
    const updateParams = [username, name, email, department]

    // Handle profile image update
    let newProfileImage = currentEmployee.profile_image

    if (removeImage === "true") {
      // Remove existing image
      if (currentEmployee.profile_image) {
        const imagePath = path.join(uploadsDir, currentEmployee.profile_image)
        fs.unlink(imagePath, (err) => {
          if (err) console.error("Error deleting old image:", err)
        })
      }
      newProfileImage = null
    } else if (req.file) {
      // New image uploaded
      if (currentEmployee.profile_image) {
        const oldImagePath = path.join(uploadsDir, currentEmployee.profile_image)
        fs.unlink(oldImagePath, (err) => {
          if (err) console.error("Error deleting old image:", err)
        })
      }
      newProfileImage = req.file.filename
    }

    updateQuery += ", profile_image = ?"
    updateParams.push(newProfileImage)

    // Handle password update
    if (password && password.trim() !== "") {
      const hashedPassword = bcrypt.hashSync(password, 10)
      updateQuery += ", password = ?"
      updateParams.push(hashedPassword)
    }

    updateQuery += " WHERE id = ? AND role = 'user'"
    updateParams.push(employeeId)

    db.run(updateQuery, updateParams, function (err) {
      if (err) {
        console.error(err)
        // Delete uploaded file if database update fails
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }

        if (err.code === "SQLITE_CONSTRAINT") {
          return db.get(
            'SELECT id, username, name, email, department, profile_image FROM users WHERE id = ? AND role = "user"',
            [employeeId],
            (err, employee) => {
              if (err || !employee) {
                return res.render("error", { message: "Employee not found", user: req.session })
              }
              res.render("admin/edit-employee", {
                user: req.session,
                employee,
                error: "Username already exists",
              })
            },
          )
        }
        return db.get(
          'SELECT id, username, name, email, department, profile_image FROM users WHERE id = ? AND role = "user"',
          [employeeId],
          (err, employee) => {
            if (err || !employee) {
              return res.render("error", { message: "Employee not found", user: req.session })
            }
            res.render("admin/edit-employee", {
              user: req.session,
              employee,
              error: "Database error occurred",
            })
          },
        )
      }

      if (this.changes === 0) {
        return res.render("error", { message: "Employee not found", user: req.session })
      }

      res.redirect("/admin/employees")
    })
  })
})

// Delete Employee Route
app.post("/admin/delete-employee/:id", requireAuth, requireAdmin, (req, res) => {
  const employeeId = req.params.id

  // Get employee data to delete profile image
  db.get('SELECT profile_image FROM users WHERE id = ? AND role = "user"', [employeeId], (err, employee) => {
    if (err) {
      console.error("Error fetching employee:", err)
      return res.render("error", { message: "Database error", user: req.session })
    }

    // Start a transaction to delete employee and related data
    db.serialize(() => {
      // Delete related attendance records
      db.run("DELETE FROM attendance WHERE user_id = ?", [employeeId], (err) => {
        if (err) {
          console.error("Error deleting attendance records:", err)
        }
      })

      // Delete related leave applications
      db.run("DELETE FROM leave_applications WHERE user_id = ?", [employeeId], (err) => {
        if (err) {
          console.error("Error deleting leave applications:", err)
        }
      })

      // Delete the employee
      db.run('DELETE FROM users WHERE id = ? AND role = "user"', [employeeId], function (err) {
        if (err) {
          console.error("Error deleting employee:", err)
          return res.render("error", { message: "Database error", user: req.session })
        }

        if (this.changes === 0) {
          return res.render("error", { message: "Employee not found", user: req.session })
        }

        // Delete profile image if exists
        if (employee && employee.profile_image) {
          const imagePath = path.join(uploadsDir, employee.profile_image)
          fs.unlink(imagePath, (err) => {
            if (err) console.error("Error deleting profile image:", err)
          })
        }

        res.redirect("/admin/employees")
      })
    })
  })
})

// View Employee Details Route
app.get("/admin/view-employee/:id", requireAuth, requireAdmin, (req, res) => {
  const employeeId = req.params.id

  // Get employee details
  db.get(
    'SELECT id, username, name, email, department, profile_image, created_at FROM users WHERE id = ? AND role = "user"',
    [employeeId],
    (err, employee) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      if (!employee) {
        return res.render("error", { message: "Employee not found", user: req.session })
      }

      // Get employee's attendance summary
      db.all(
        `SELECT 
          COUNT(*) as total_days,
          SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present_days,
          SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent_days
        FROM attendance WHERE user_id = ?`,
        [employeeId],
        (err, attendanceSummary) => {
          if (err) {
            console.error(err)
            return res.render("error", { message: "Database error", user: req.session })
          }

          // Get recent attendance records
          db.all(
            "SELECT * FROM attendance WHERE user_id = ? ORDER BY date DESC LIMIT 10",
            [employeeId],
            (err, recentAttendance) => {
              if (err) {
                console.error(err)
                return res.render("error", { message: "Database error", user: req.session })
              }

              // Get leave applications
              db.all(
                "SELECT * FROM leave_applications WHERE user_id = ? ORDER BY created_at DESC",
                [employeeId],
                (err, leaveApplications) => {
                  if (err) {
                    console.error(err)
                    return res.render("error", { message: "Database error", user: req.session })
                  }

                  res.render("admin/view-employee", {
                    user: req.session,
                    employee,
                    attendanceSummary: attendanceSummary[0] || {
                      total_days: 0,
                      present_days: 0,
                      absent_days: 0,
                    },
                    recentAttendance,
                    leaveApplications,
                  })
                },
              )
            },
          )
        },
      )
    },
  )
})

// Bulk Operations Route
app.get("/admin/bulk-operations", requireAuth, requireAdmin, (req, res) => {
  db.all('SELECT id, username, name, email, department FROM users WHERE role = "user"', (err, employees) => {
    if (err) {
      console.error(err)
      return res.render("error", { message: "Database error", user: req.session })
    }

    res.render("admin/bulk-operations", { user: req.session, employees, message: null })
  })
})

// Bulk Delete Route
app.post("/admin/bulk-delete", requireAuth, requireAdmin, (req, res) => {
  const { selectedEmployees } = req.body

  if (!selectedEmployees || selectedEmployees.length === 0) {
    return db.all('SELECT id, username, name, email, department FROM users WHERE role = "user"', (err, employees) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }
      res.render("admin/bulk-operations", {
        user: req.session,
        employees,
        message: "Please select at least one employee to delete",
      })
    })
  }

  const employeeIds = Array.isArray(selectedEmployees) ? selectedEmployees : [selectedEmployees]
  const placeholders = employeeIds.map(() => "?").join(",")

  // Get profile images to delete
  db.all(
    `SELECT profile_image FROM users WHERE id IN (${placeholders}) AND role = 'user'`,
    employeeIds,
    (err, employees) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      db.serialize(() => {
        // Delete related records first
        db.run(`DELETE FROM attendance WHERE user_id IN (${placeholders})`, employeeIds)
        db.run(`DELETE FROM leave_applications WHERE user_id IN (${placeholders})`, employeeIds)

        // Delete employees
        db.run(`DELETE FROM users WHERE id IN (${placeholders}) AND role = 'user'`, employeeIds, (err) => {
          if (err) {
            console.error("Error in bulk delete:", err)
            return res.render("error", { message: "Database error", user: req.session })
          }

          // Delete profile images
          employees.forEach((employee) => {
            if (employee.profile_image) {
              const imagePath = path.join(uploadsDir, employee.profile_image)
              fs.unlink(imagePath, (err) => {
                if (err) console.error("Error deleting profile image:", err)
              })
            }
          })

          res.redirect("/admin/employees")
        })
      })
    },
  )
})

app.post("/admin/bulk-attendance", requireAuth, requireAdmin, (req, res) => {
  const { action, date, selectedEmployees } = req.body

  if (!action || !date) {
    return res.redirect("/admin/attendance-management?error=Missing required fields")
  }

  const query = ""
  const params = []

  switch (action) {
    case "mark-all-present":
      // Mark all employees as present
      db.all('SELECT id FROM users WHERE role = "user"', (err, users) => {
        if (err) {
          console.error("Error fetching users:", err)
          return res.redirect("/admin/attendance-management?error=Database error")
        }

        const promises = users.map((user) => {
          return new Promise((resolve, reject) => {
            db.run(
              "INSERT OR REPLACE INTO attendance (user_id, date, status) VALUES (?, ?, ?)",
              [user.id, date, "present"],
              (err) => {
                if (err) reject(err)
                else resolve()
              },
            )
          })
        })

        Promise.all(promises)
          .then(() => {
            res.redirect("/admin/attendance-management?success=All employees marked as present")
          })
          .catch((err) => {
            console.error("Bulk attendance error:", err)
            res.redirect("/admin/attendance-management?error=Failed to mark attendance")
          })
      })
      break

    case "mark-all-absent":
      // Mark all employees as absent
      db.all('SELECT id FROM users WHERE role = "user"', (err, users) => {
        if (err) {
          console.error("Error fetching users:", err)
          return res.redirect("/admin/attendance-management?error=Database error")
        }

        const promises = users.map((user) => {
          return new Promise((resolve, reject) => {
            db.run(
              "INSERT OR REPLACE INTO attendance (user_id, date, status) VALUES (?, ?, ?)",
              [user.id, date, "absent"],
              (err) => {
                if (err) reject(err)
                else resolve()
              },
            )
          })
        })

        Promise.all(promises)
          .then(() => {
            res.redirect("/admin/attendance-management?success=All employees marked as absent")
          })
          .catch((err) => {
            console.error("Bulk attendance error:", err)
            res.redirect("/admin/attendance-management?error=Failed to mark attendance")
          })
      })
      break

    case "mark-selected-present":
    case "mark-selected-absent":
      if (!selectedEmployees || selectedEmployees.length === 0) {
        return res.redirect("/admin/attendance-management?error=No employees selected")
      }

      const employeeIds = Array.isArray(selectedEmployees) ? selectedEmployees : [selectedEmployees]
      const status = action.includes("present") ? "present" : "absent"

      const promises = employeeIds.map((userId) => {
        return new Promise((resolve, reject) => {
          db.run(
            "INSERT OR REPLACE INTO attendance (user_id, date, status) VALUES (?, ?, ?)",
            [userId, date, status],
            (err) => {
              if (err) reject(err)
              else resolve()
            },
          )
        })
      })

      Promise.all(promises)
        .then(() => {
          res.redirect(`/admin/attendance-management?success=${employeeIds.length} employee(s) marked as ${status}`)
        })
        .catch((err) => {
          console.error("Bulk attendance error:", err)
          res.redirect("/admin/attendance-management?error=Failed to mark attendance")
        })
      break

    default:
      res.redirect("/admin/attendance-management?error=Invalid action")
  }
})

// User Routes
app.get("/user/dashboard", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  // Get user's recent attendance
  db.all(
    `SELECT * FROM attendance 
     WHERE user_id = ? 
     ORDER BY date DESC 
     LIMIT 5`,
    [req.session.userId],
    (err, attendance) => {
      if (err) {
        console.error("Attendance fetch error:", err)
        attendance = []
      }

      // Get user's recent leave applications
      db.all(
        `SELECT * FROM leave_applications 
         WHERE user_id = ? 
         ORDER BY created_at DESC 
         LIMIT 5`,
        [req.session.userId],
        (err, leaves) => {
          if (err) {
            console.error("Leaves fetch error:", err)
            leaves = []
          }

          // Check if user is currently on leave
          db.get(
            `SELECT * FROM leave_applications 
             WHERE user_id = ? 
             AND status = 'approved' 
             AND date('now') BETWEEN start_date AND end_date
             AND (absence_status = 'on-leave' OR absence_status IS NULL)
             ORDER BY created_at DESC LIMIT 1`,
            [req.session.userId],
            (err, currentLeave) => {
              if (err) {
                console.error("Current leave fetch error:", err)
                currentLeave = null
              }

              res.render("user/dashboard", {
                user: req.session,
                attendance: attendance || [],
                leaves: leaves || [],
                currentLeave: currentLeave || null,
                error: req.query.error || null,
                success: req.query.success || null,
              })
            },
          )
        },
      )
    },
  )
})

app.get("/user/attendance", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  // Check if user already marked attendance today
  const today = new Date().toISOString().split("T")[0]

  db.get(
    "SELECT * FROM attendance WHERE user_id = ? AND date = ?",
    [req.session.userId, today],
    (err, todayAttendance) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      // Get recent attendance records
      db.all(
        "SELECT * FROM attendance WHERE user_id = ? ORDER BY date DESC LIMIT 10",
        [req.session.userId],
        (err, attendance) => {
          if (err) {
            console.error(err)
            return res.render("error", { message: "Database error", user: req.session })
          }

          res.render("user/attendance", {
            user: req.session,
            attendance,
            todayAttendance,
            today,
          })
        },
      )
    },
  )
})

app.post("/user/mark-attendance", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  const { status } = req.body
  const today = new Date().toISOString().split("T")[0]
  const attendanceStatus = status || "present"

  db.run(
    "INSERT OR REPLACE INTO attendance (user_id, date, status) VALUES (?, ?, ?)",
    [req.session.userId, today, attendanceStatus],
    (err) => {
      if (err) {
        console.error("Error marking attendance:", err)
        return res.redirect("/user/attendance?error=Failed to mark attendance")
      }
      res.redirect(`/user/attendance?success=Attendance marked as ${attendanceStatus}`)
    },
  )
})

app.post("/admin/mark-attendance", requireAuth, requireAdmin, (req, res) => {
  const { userId, date, status } = req.body

  if (!userId || !date || !status) {
    return res.redirect("/admin/employees?error=Missing required fields")
  }

  db.run(
    "INSERT OR REPLACE INTO attendance (user_id, date, status) VALUES (?, ?, ?)",
    [userId, date, status],
    (err) => {
      if (err) {
        console.error("Error marking attendance:", err)
        return res.redirect("/admin/employees?error=Failed to mark attendance")
      }
      res.redirect(`/admin/employees?success=Attendance marked as ${status}`)
    },
  )
})

app.get("/admin/attendance-management", requireAuth, requireAdmin, (req, res) => {
  const today = new Date().toISOString().split("T")[0]

  // Get all employees with today's attendance status
  db.all(
    `SELECT u.id, u.name, u.department, u.profile_image,
            a.status as attendance_status, a.date as attendance_date,
            es.status as employee_status
     FROM users u
     LEFT JOIN attendance a ON u.id = a.user_id AND a.date = ?
     LEFT JOIN employee_status es ON u.id = es.user_id
     WHERE u.role = 'user'
     ORDER BY u.name`,
    [today],
    (err, employees) => {
      if (err) {
        console.error("Error fetching attendance data:", err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      res.render("admin/attendance-management", {
        user: req.session,
        employees: employees || [],
        today,
        error: req.query.error || null,
        success: req.query.success || null,
      })
    },
  )
})

app.get("/user/leave", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  db.all(
    "SELECT * FROM leave_applications WHERE user_id = ? ORDER BY created_at DESC",
    [req.session.userId],
    (err, applications) => {
      if (err) {
        console.error("Leave applications fetch error:", err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      res.render("user/leave", {
        user: req.session,
        applications: applications || [],
        error: req.query.error || null,
        success: req.query.success || null,
      })
    },
  )
})

app.post("/user/apply-leave", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  const { startDate, endDate, reason } = req.body

  // Validate required fields
  if (!startDate || !endDate || !reason || reason.trim() === "") {
    return res.redirect("/user/leave?error=All fields are required")
  }

  // Validate dates
  const start = new Date(startDate)
  const end = new Date(endDate)
  const today = new Date()
  today.setHours(0, 0, 0, 0)

  if (start > end) {
    return res.redirect("/user/leave?error=End date must be after start date")
  }

  if (start < today) {
    return res.redirect("/user/leave?error=Start date cannot be in the past")
  }

  // Check for overlapping leave applications (pending or approved)
  db.get(
    `SELECT id, status, start_date, end_date FROM leave_applications 
     WHERE user_id = ? 
     AND status IN ('pending', 'approved')
     AND ((start_date <= ? AND end_date >= ?) 
          OR (start_date <= ? AND end_date >= ?)
          OR (? <= start_date AND ? >= end_date))`,
    [req.session.userId, startDate, startDate, endDate, endDate, startDate, endDate],
    (err, existingLeave) => {
      if (err) {
        console.error("Leave overlap check error:", err)
        return res.redirect("/user/leave?error=Database error")
      }

      if (existingLeave) {
        const conflictStart = new Date(existingLeave.start_date).toLocaleDateString()
        const conflictEnd = new Date(existingLeave.end_date).toLocaleDateString()
        return res.redirect(
          `/user/leave?error=You already have a ${existingLeave.status} leave application from ${conflictStart} to ${conflictEnd}`,
        )
      }

      // Insert new leave application
      db.run(
        "INSERT INTO leave_applications (user_id, start_date, end_date, reason) VALUES (?, ?, ?, ?)",
        [req.session.userId, startDate, endDate, reason.trim()],
        (err) => {
          if (err) {
            console.error("Leave application error:", err)
            return res.redirect("/user/leave?error=Failed to submit leave application")
          }
          res.redirect("/user/leave?success=Leave application submitted successfully")
        },
      )
    },
  )
})

// User Profile Routes
app.get("/user/profile", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  // Get user's complete profile information
  db.get(
    "SELECT id, username, name, email, department, profile_image, created_at FROM users WHERE id = ?",
    [req.session.userId],
    (err, userProfile) => {
      if (err) {
        console.error(err)
        return res.render("error", { message: "Database error", user: req.session })
      }

      if (!userProfile) {
        return res.render("error", { message: "User profile not found", user: req.session })
      }

      // Get user's attendance summary
      db.all(
        `SELECT 
          COUNT(*) as total_days,
          SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present_days,
          SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent_days
        FROM attendance WHERE user_id = ?`,
        [req.session.userId],
        (err, attendanceSummary) => {
          if (err) {
            console.error(err)
            return res.render("error", { message: "Database error", user: req.session })
          }

          // Get leave applications summary
          db.all(
            `SELECT 
              COUNT(*) as total_applications,
              SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_leaves,
              SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_leaves,
              SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_leaves
            FROM leave_applications WHERE user_id = ?`,
            [req.session.userId],
            (err, leaveSummary) => {
              if (err) {
                console.error(err)
                return res.render("error", { message: "Database error", user: req.session })
              }

              res.render("user/profile", {
                user: req.session,
                userProfile,
                attendanceSummary: attendanceSummary[0] || {
                  total_days: 0,
                  present_days: 0,
                  absent_days: 0,
                },
                leaveSummary: leaveSummary[0] || {
                  total_applications: 0,
                  approved_leaves: 0,
                  pending_leaves: 0,
                  rejected_leaves: 0,
                },
                error: null,
                success: null,
              })
            },
          )
        },
      )
    },
  )
})

// Update User Profile Route
app.post("/user/update-profile", requireAuth, upload.single("profileImage"), (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  const { name, email, currentPassword, newPassword, confirmPassword, removeImage } = req.body

  if (!name) {
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting file:", err)
      })
    }
    return res.redirect("/user/profile?error=Name is required")
  }

  // Get current user data for validation
  db.get("SELECT * FROM users WHERE id = ?", [req.session.userId], (err, currentUser) => {
    if (err) {
      console.error(err)
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting file:", err)
        })
      }
      return res.redirect("/user/profile?error=Database error")
    }

    if (!currentUser) {
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting file:", err)
        })
      }
      return res.redirect("/user/profile?error=User not found")
    }

    // Handle profile image update
    let newProfileImage = currentUser.profile_image

    if (removeImage === "true") {
      // Remove existing image
      if (currentUser.profile_image) {
        const imagePath = path.join(uploadsDir, currentUser.profile_image)
        fs.unlink(imagePath, (err) => {
          if (err) console.error("Error deleting old image:", err)
        })
      }
      newProfileImage = null
    } else if (req.file) {
      // New image uploaded
      if (currentUser.profile_image) {
        const oldImagePath = path.join(uploadsDir, currentUser.profile_image)
        fs.unlink(oldImagePath, (err) => {
          if (err) console.error("Error deleting old image:", err)
        })
      }
      newProfileImage = req.file.filename
    }

    // Check if password change is requested
    if (newPassword && newPassword.trim() !== "") {
      // Validate current password
      if (!currentPassword || !bcrypt.compareSync(currentPassword, currentUser.password)) {
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }
        return res.redirect("/user/profile?error=Current password is incorrect")
      }

      // Validate new password confirmation
      if (newPassword !== confirmPassword) {
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }
        return res.redirect("/user/profile?error=New passwords do not match")
      }

      // Validate new password strength
      if (newPassword.length < 6) {
        if (req.file) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting file:", err)
          })
        }
        return res.redirect("/user/profile?error=New password must be at least 6 characters long")
      }

      // Update with new password
      const hashedPassword = bcrypt.hashSync(newPassword, 10)
      db.run(
        "UPDATE users SET name = ?, email = ?, password = ?, profile_image = ? WHERE id = ?",
        [name, email, hashedPassword, newProfileImage, req.session.userId],
        (err) => {
          if (err) {
            console.error(err)
            if (req.file) {
              fs.unlink(req.file.path, (err) => {
                if (err) console.error("Error deleting file:", err)
              })
            }
            return res.redirect("/user/profile?error=Database error occurred")
          }

          // Update session name
          req.session.name = name
          res.redirect("/user/profile?success=Profile and password updated successfully")
        },
      )
    } else {
      // Update without password change
      db.run(
        "UPDATE users SET name = ?, email = ?, profile_image = ? WHERE id = ?",
        [name, email, newProfileImage, req.session.userId],
        (err) => {
          if (err) {
            console.error(err)
            if (req.file) {
              fs.unlink(req.file.path, (err) => {
                if (err) console.error("Error deleting file:", err)
              })
            }
            return res.redirect("/user/profile?error=Database error occurred")
          }

          // Update session name
          req.session.name = name
          res.redirect("/user/profile?success=Profile updated successfully")
        },
      )
    }
  })
})

// User mark return functionality
app.post("/user/mark-return", requireAuth, (req, res) => {
  if (req.session.role === "admin") {
    return res.redirect("/admin/dashboard")
  }

  const { applicationId } = req.body

  db.run(
    `UPDATE leave_applications 
     SET absence_status = 'returned', actual_return_date = date('now'), updated_at = datetime('now')
     WHERE id = ? AND user_id = ? AND status = 'approved'`,
    [applicationId, req.session.userId],
    function (err) {
      if (err) {
        console.error("Error marking return:", err)
        return res.redirect("/user/dashboard?error=Failed to mark return")
      }

      if (this.changes === 0) {
        return res.redirect("/user/dashboard?error=No valid leave found to mark return")
      }

      // Update employee status
      updateEmployeeStatus(req.session.userId, () => {
        res.redirect("/user/dashboard?success=Return marked successfully")
      })
    },
  )
})

// Admin mark return functionality
app.post("/admin/mark-return", requireAuth, requireAdmin, (req, res) => {
  const { applicationId, userId } = req.body

  db.run(
    `UPDATE leave_applications 
     SET absence_status = 'returned', actual_return_date = date('now'), updated_at = datetime('now')
     WHERE id = ? AND status = 'approved'`,
    [applicationId],
    (err) => {
      if (err) {
        console.error("Error marking return:", err)
        return res.redirect("/admin/absence-management?error=Failed to mark return")
      }

      // Update employee status
      updateEmployeeStatus(userId, () => {
        res.redirect("/admin/absence-management?success=Employee return marked successfully")
      })
    },
  )
})

app.get("/admin/absence-management", requireAuth, requireAdmin, (req, res) => {
  // Get current absentees
  db.all(
    `SELECT la.*, u.name as employee_name, u.department
     FROM leave_applications la
     JOIN users u ON la.user_id = u.id
     WHERE la.status = 'approved' 
     AND date('now') BETWEEN la.start_date AND la.end_date
     AND (la.absence_status = 'on-leave' OR la.absence_status IS NULL)
     ORDER BY la.end_date ASC`,
    (err, currentAbsentees) => {
      if (err) {
        console.error("Current absentees error:", err)
        return res.render("error", { message: "Database error loading current absentees", user: req.session })
      }

      // Get absence history (last 50 records)
      db.all(
        `SELECT la.*, u.name as employee_name, u.department
         FROM leave_applications la
         JOIN users u ON la.user_id = u.id
         WHERE la.status = 'approved'
         ORDER BY la.created_at DESC
         LIMIT 50`,
        (err, absenceHistory) => {
          if (err) {
            console.error("Absence history error:", err)
            return res.render("error", { message: "Database error loading absence history", user: req.session })
          }

          // Get absence statistics
          db.all(
            `SELECT 
               COUNT(*) as monthly_absences,
               ROUND(AVG(julianday(end_date) - julianday(start_date) + 1), 1) as avg_duration,
               (SELECT reason FROM leave_applications WHERE status = 'approved' 
                GROUP BY reason ORDER BY COUNT(*) DESC LIMIT 1) as common_reason
             FROM leave_applications 
             WHERE status = 'approved' 
             AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')`,
            (err, statsResult) => {
              if (err) {
                console.error("Absence stats error:", err)
                // Continue with empty stats rather than failing
              }

              const stats =
                statsResult && statsResult[0]
                  ? statsResult[0]
                  : {
                      monthly_absences: 0,
                      avg_duration: 0,
                      common_reason: "N/A",
                    }

              res.render("admin/absence-management", {
                user: req.session,
                currentAbsentees: currentAbsentees || [],
                absenceHistory: absenceHistory || [],
                stats,
                error: req.query.error || null,
                success: req.query.success || null,
              })
            },
          )
        },
      )
    },
  )
})

// Run status updates every hour
setInterval(updateAllEmployeeStatuses, 60 * 60 * 1000)

// Run initial status update
setTimeout(updateAllEmployeeStatuses, 5000)

// Initialize database and start server
initializeDatabase()

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
  console.log("Default admin credentials: username: admin, password: admin123")
})
