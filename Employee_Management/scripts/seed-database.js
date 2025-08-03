const sqlite3 = require("sqlite3").verbose()
const bcrypt = require("bcrypt")

const db = new sqlite3.Database("./database.db")

// Sample data for testing
const sampleEmployees = [
  {
    username: "john.doe",
    password: "password123",
    name: "John Doe",
    email: "john.doe@company.com",
    department: "Engineering",
  },
  {
    username: "jane.smith",
    password: "password123",
    name: "Jane Smith",
    email: "jane.smith@company.com",
    department: "HR",
  },
  {
    username: "mike.johnson",
    password: "password123",
    name: "Mike Johnson",
    email: "mike.johnson@company.com",
    department: "Marketing",
  },
]

console.log("Seeding database with sample data...")

// Insert sample employees
sampleEmployees.forEach((employee, index) => {
  const hashedPassword = bcrypt.hashSync(employee.password, 10)

  db.run(
    "INSERT OR IGNORE INTO users (username, password, name, email, department, role) VALUES (?, ?, ?, ?, ?, ?)",
    [employee.username, hashedPassword, employee.name, employee.email, employee.department, "user"],
    function (err) {
      if (err) {
        console.error(`Error inserting ${employee.name}:`, err.message)
      } else {
        console.log(`✓ Added employee: ${employee.name}`)

        // Add some sample attendance records
        const userId = this.lastID
        if (userId) {
          // Add attendance for the last 5 days
          for (let i = 0; i < 5; i++) {
            const date = new Date()
            date.setDate(date.getDate() - i)
            const dateString = date.toISOString().split("T")[0]

            db.run(
              "INSERT OR IGNORE INTO attendance (user_id, date, status) VALUES (?, ?, ?)",
              [userId, dateString, "present"],
              (err) => {
                if (err) {
                  console.error(`Error adding attendance for ${employee.name}:`, err.message)
                }
              },
            )
          }

          // Add a sample leave application
          if (index === 0) {
            // Only for first employee
            const startDate = new Date()
            startDate.setDate(startDate.getDate() + 7)
            const endDate = new Date()
            endDate.setDate(endDate.getDate() + 9)

            db.run(
              "INSERT OR IGNORE INTO leave_applications (user_id, start_date, end_date, reason, status) VALUES (?, ?, ?, ?, ?)",
              [
                userId,
                startDate.toISOString().split("T")[0],
                endDate.toISOString().split("T")[0],
                "Personal work",
                "pending",
              ],
              (err) => {
                if (err) {
                  console.error(`Error adding leave application for ${employee.name}:`, err.message)
                } else {
                  console.log(`✓ Added sample leave application for ${employee.name}`)
                }
              },
            )
          }
        }
      }
    },
  )
})

setTimeout(() => {
  console.log("\nDatabase seeding completed!")
  console.log("\nSample login credentials:")
  console.log("Admin: username: admin, password: admin123")
  console.log("Employee 1: username: john.doe, password: password123")
  console.log("Employee 2: username: jane.smith, password: password123")
  console.log("Employee 3: username: mike.johnson, password: password123")

  db.close()
}, 2000)
