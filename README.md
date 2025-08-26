Research Review Portal

Overview
This application allows the creation of admin and user login pages. The admin serves as a supervisor who manages and tracks the activities of various users. The primary functionality of the admin is to validate the quality of research papers submitted by users and offer constructive feedback to improve their work.

Features
- User Authentication: Secure login and registration system with role-based access (User/Admin)
- Research Paper Submission: Users can submit their research papers for validation by the admin.
- Document Management: Upload, view, and manage research papers with drag-and-drop support
- Admin Feedback:Admin can review and provide feedback on users' research papers.
- User Dashboard: Users can track the status of their submissions and feedback provided by the admin.
- Admin Dashboard: Admin can view, validate, and comment on multiple submissions from users.
- Notification: Real-time notification system for important events

Technologies Used
- Backend: Python (Flask)
- Frontend: HTML, CSS, JavaScript
- Database: MongoDB Atlas
- Other Tools: Python libraries such as Flask for the web framework


File Structure 
Research-Review-Portal/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env                  # Environment variables
├── uploads/              # Document storage directory
├── static/               # Static assets
│   ├── css/              # Stylesheets
│   ├── js/               # JavaScript files
│   └── images/           # Image assets
└── templates/            # HTML templates
    ├── base.html         # Base template
    ├── login.html        # Login page
    ├── register.html     # Registration page
    ├── user_dashboard.html  # User dashboard
    ├── admin_dashboard.html # Admin dashboard
    ├── profile.html      # User profile
    ├── notifications.html # Notifications page
    └── 404.html          # 404 error page