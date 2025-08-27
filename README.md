Research Review Portal

Overview
The Research Review Portal is a secure, role-based web application designed to streamline research paper submission, validation, and feedback processes between students, teachers, and administrators. It enables smooth collaboration, document management, and real-time notifications for all stakeholders.

Features
- User Authentication: Register and login for students and teachers. Admin login with default credentials.
- Role-Based Dashboards
- Admin: Manage users, assign teachers to students, view stats.
- Teacher: Review student submissions and give feedback.
- Student: Upload research papers and view feedback.
- Research Paper Submission: Students can submit their research papers for validation by the teacher.
- Document Management: Upload, view, and manage research papers with drag-and-drop support.
- Teacher Feedback:Teacher can review and provide feedback on users' research papers.
- Student Dashboard: Students can track the status of their submissions and feedback provided by the teacher.
- Notification: Real-time notification system for important events

Technologies Used
- Backend: Python (Flask)
- Frontend: HTML, CSS, JavaScript
- Database: MongoDB Atlas
- Other Tools: Python libraries such as Flask for the web framework

--- 
## File Structure 

```

Research-Review-Portal/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env                  # Environment variables
├── uploads/              # Document storage directory
├── static/               # Static assets
│   ├── css/              # Stylesheets
│   ├── js/               # JavaScript files
└── templates/            # HTML templates
    ├── base.html         # Base template
    ├── login.html        # Login page
    ├── register.html     # Registration page
    ├── user_dashboard.html  # User dashboard
    ├── admin_dashboard.html # Admin dashboard
    ├── profile.html      # User profile
    ├── notifications.html # Notifications page
    └── 404.html          # 404 error page

```

---