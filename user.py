import bcrypt
import mysql.connector
from mysql.connector import Error
from datetime import datetime

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def store_user_with_role_permissions():
    name = 'satyendra'
    email = 'satyendra@gmail.com'
    password = '1234'
    is_active = '1'
    created_at = updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    hashed_password = hash_password(password)

    try:

        connection = mysql.connector.connect(host='localhost', user='root', password='password', database='houston_vms')

        if connection.is_connected():
            cursor = connection.cursor()
            connection.start_transaction()

            user_query = """
                INSERT INTO user (name, email, password, is_active, created_at, updated_at) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(user_query, (name, email, hashed_password, is_active, created_at, updated_at))
            user_id = cursor.lastrowid

            # Insert role
            role_name = "admin"
            role_query = "INSERT INTO role (name) VALUES (%s)"
            cursor.execute(role_query, (role_name,))  # Add comma to make it a tuple
            role_id = cursor.lastrowid
            cursor.execute(role_query, (role_name))
            role_id = cursor.lastrowid

            # Define permissions with keys and names
            permissions = [
                ("create_user", "Can Create User"),
                ("view_user", "Can View User"),
                ("edit_user", "Can Edit User"),
                ("delete_user", "Can Delete User")
            ]
            permission_ids = []

            # Insert permissions
            for permission_key, permission_name in permissions:
                permission_query = "INSERT INTO permission (permission_key, permission_name) VALUES (%s, %s)"
                cursor.execute(permission_query, (permission_key, permission_name))
                permission_ids.append(cursor.lastrowid)

            # Assign user to role
            user_role_query = "INSERT INTO user_role (user_id, role_id) VALUES (%s, %s)"
            cursor.execute(user_role_query, (user_id, role_id))

            # Assign permissions to role
            for perm_id in permission_ids:
                role_permission_query = "INSERT INTO role_permission (role_id, permission_id) VALUES (%s, %s)"
                cursor.execute(role_permission_query, (role_id, perm_id))

            # Commit transaction
            connection.commit()
            print(f"User '{name}' added with role '{role_name}' and permissions: {permissions}")

    except Error as e:
        connection.rollback()
        print(f"Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Insert user, role, and permissions
if __name__ == "__main__":
    store_user_with_role_permissions()
