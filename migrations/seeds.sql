INSERT INTO permissions (name, description)
VALUES
  ('manage_users', 'Admin can manage all users'),
  ('create_room', 'Facilitator can create a room'),
  ('create_quiz', 'Facilitator can create quizzes'),
  ('join_room', 'Learner can join a room'),
  ('complete_quiz', 'Learner can complete a quiz');

INSERT INTO roles (name, description)
VALUES
  ('admin', 'System administrator'),
  ('facilitator', 'Creates rooms and quizzes'),
  ('learner', 'Joins rooms and completes quizzes');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p ON (
    (r.name = 'admin' AND p.name IN ('manage_users', 'create_room', 'create_quiz', 'join_room', 'complete_quiz')) OR
    (r.name = 'facilitator' AND p.name IN ('create_room', 'create_quiz')) OR
    (r.name = 'learner' AND p.name IN ('join_room', 'complete_quiz'))
);


INSERT INTO permissions (name, description)
VALUES
  ('menu_user', 'Role can access menu user'),
  ('menu_create_quiz', 'Role can access menu create quiz'),
  ('menu_quiz', 'Role can access menu quiz');


INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p ON (
    (r.name = 'admin' AND p.name IN ('menu_user')) OR
    (r.name = 'facilitator' AND p.name IN ('menu_create_quiz')) OR
    (r.name = 'learner' AND p.name IN ('menu_quiz'))
);

