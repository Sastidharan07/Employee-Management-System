# Employee Management System

A complete employee management system built with Node.js, Express.js, SQLite, and EJS templates. This system provides role-based access control for administrators and employees with features for attendance tracking and leave management.

## Features

### Authentication & Security
- Secure login system with bcrypt password hashing
- Session-based authentication using express-session
- Role-based access control (Admin/User)
- Admin-only user creation (no self-registration)

### Admin Features
- Admin dashboard with statistics
- Add, view, and manage employees
- Approve or reject leave applications
- View attendance and leave summaries

### Employee Features
- Employee dashboard
- Mark daily attendance
- Apply for leave
- View leave application status
- View attendance history

## Technology Stack

- **Frontend**: HTML, CSS, EJS (Embedded JavaScript Templates)
- **Backend**: Node.js with Express.js
- **Database**: SQLite (file-based, fully free)
- **Authentication**: express-session, bcrypt

## Installation

1. Clone or download the project files
2. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`

3. Start the server:
   \`\`\`bash
   npm start
   \`\`\`
   
   For development with auto-restart:
   \`\`\`bash
   npm run dev
   \`\`\`

4. Open your browser and navigate to `http://localhost:3000`

## Default Credentials

**Admin Login:**
- Username: `admin`
- Password: `admin123`

## Database Setup

The application automatically creates the necessary SQLite database and tables on first run. The database file (`database.db`) will be created in the project root directory.

### Database Schema

**Users Table:**
- id (Primary Key)
- username (Unique)
- password (Hashed)
- role (admin/user)
- name
- email
- department
- created_at

**Attendance Table:**
- id (Primary Key)
- user_id (Foreign Key)
- date
- status (present/absent)
- created_at

**Leave Applications Table:**
- id (Primary Key)
- user_id (Foreign Key)
- start_date
- end_date
- reason
- status (pending/approved/rejected)
- admin_comment
- created_at

## Sample Data

To populate the database with sample employees and data, run:

\`\`\`bash
node scripts/seed-database.js
\`\`\`

This will create sample employees with the following credentials:
- Username: `john.doe`, Password: `password123`
- Username: `jane.smith`, Password: `password123`
- Username: `mike.johnson`, Password: `password123`

## Usage

### Admin Workflow
1. Login with admin credentials
2. Access admin dashboard to view statistics
3. Add new employees via "Add Employee" page
4. Review and approve/reject leave applications
5. Monitor attendance and leave summaries

### Employee Workflow
1. Login with employee credentials (created by admin)
2. Mark daily attendance
3. Apply for leave with start date, end date, and reason
4. View leave application status and history
5. Check attendance records

## Security Features

- Passwords are securely hashed using bcrypt
- Session-based authentication prevents unauthorized access
- Role-based middleware protects admin routes
- SQL injection protection through parameterized queries
- CSRF protection through session validation

## File Structure

\`\`\`
employee-management-system/
├── server.js                 # Main server file
├── package.json              # Dependencies and scripts
├── database.db               # SQLite database (auto-created)
├── public/
│   └── styles.css           # CSS styles
├── views/
│   ├── layout.ejs           # Main layout template
│   ├── login.ejs            # Login page
│   ├── error.ejs            # Error page
│   ├── admin/
│   │   ├── dashboard.ejs    # Admin dashboard
│   │   ├── employees.ejs    # Employee management
│   │   ├── add-employee.ejs # Add employee form
│   │   └── leave-applications.ejs # Leave management
│   └── user/
│       ├── dashboard.ejs    # User dashboard
│       ├── attendance.ejs   # Attendance management
│       └── leave.ejs        # Leave application
└── scripts/
    └── seed-database.js     # Database seeding script
\`\`\`

## Customization

### Adding New Features
- Modify the database schema in `server.js`
- Add new routes for additional functionality
- Create corresponding EJS templates
- Update the CSS for styling

### Changing Styles
- Edit `public/styles.css` to customize the appearance
- The CSS includes responsive design for mobile devices
- Color scheme and layout can be easily modified

### Database Configuration
- The SQLite database file location can be changed in `server.js`
- For production, consider using PostgreSQL or MySQL
- Environment variables can be added for configuration

## Production Deployment

For production deployment:

1. Change the session secret in `server.js`
2. Set `cookie.secure` to `true` for HTTPS
3. Use environment variables for sensitive configuration
4. Consider using a process manager like PM2
5. Set up proper logging and error handling
6. Use a reverse proxy like Nginx

## License

MIT License - feel free to use this project for personal or commercial purposes.
