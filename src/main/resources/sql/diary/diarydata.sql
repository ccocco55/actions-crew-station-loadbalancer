-- init_dummy.sql : PostgreSQL 초기화 + 더미데이터 30개

-- -- 1. 기존 데이터 초기화
-- TRUNCATE TABLE
--     tbl_post_section_file,
--     tbl_file,
--     tbl_post_section,
--     tbl_like,
--     tbl_diary,
--     tbl_diary_country_path,
--     tbl_post,
--     tbl_country,
--     tbl_member
--     RESTART IDENTITY CASCADE;

Select *
from tbl_member;
Select *
from tbl_like;

UPDATE tbl_member
SET member_name = '데구르르구르는바나나'
WHERE id = 3;

-- 2. 회원
INSERT INTO tbl_member (member_name, member_email, member_password, social_img_url)
VALUES ('Alice', 'alice@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Alice'),
       ('Bob', 'bob@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Bob'),
       ('Charlie', 'charlie@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Charlie'),
       ('David', 'david@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=David'),
       ('Emma', 'emma@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Emma'),
       ('Frank', 'frank@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Frank');

-- 3. 나라
INSERT INTO tbl_country (country_name)
VALUES ('Korea'),
       ('Japan'),
       ('USA'),
       ('France'),
       ('Italy');

INSERT INTO tbl_country (country_name)
VALUES ('한국'),
       ('일본'),
       ('미국'),
       ('프랑스'),
       ('이탈리아');
-- 4. 일기 더미 데이터 (30개)

-- 1
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 2', 1),
       ('Diary Post 3', 1),
       ('Diary Post 4', 1),
       ('Diary Post 5', 1),
       ('Diary Post 6', 1),
       ('Diary Post 7', 1),
       ('Diary Post 8', 1),
       ('Diary Post 9', 1);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-01', '2025-01-10', 1, 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-01', '2025-01-10', 1, 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-01', '2025-01-10', 1, 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-01', '2025-01-10', 1, 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-01', '2025-01-10', 1, 1);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-01', '2025-01-10', 1, 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-01', '2025-01-10', 1, 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-01', '2025-01-10', 1, 4);

INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (29, 'public', 0, 0, 1),
(30, 'public', 0, 0, 2),
(31, 'public', 0, 0, 3),
(32, 'public', 0, 0, 4),
(33, 'public', 0, 0, 5),
(34, 'public', 0, 0, 6),
(35, 'public', 0, 0, 7),
(36, 'public', 0, 0, 8),
(37, 'public', 0, 0, 9);

INSERT INTO tbl_like (post_id, member_id)
VALUES (30, 1);
INSERT INTO tbl_like (post_id, member_id)
VALUES (31, 2);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 1-1', 29),
       ('Diary content 2', 30),
       ('Diary content 3', 31),
       ('Diary content 4', 32),
       ('Diary content 5', 33),
       ('Diary content 6', 34),
       ('Diary content 7', 35),
       ('Diary content 8', 36),
       ('Diary content 9', 37);

INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('Unknown.png', '2025/09/29/ce60db51-01e3-4484-bdda-7d11c2a710eb.png', '9745f486-b55a-436d-b387-9ae738ab7d20.png', '3527'),
       ('Unknown.png', '2025/09/29/ce60db51-01e3-4484-bdda-7d11c2a710eb.png', '9745f486-b55a-436d-b387-9ae738ab7d20.png', '3527'),
       ('Unknown.png', '2025/09/29/ce60db51-01e3-4484-bdda-7d11c2a710eb.png', '9745f486-b55a-436d-b387-9ae738ab7d20.png', '3527'),
       ('Unknown.png', '2025/09/29/ce60db51-01e3-4484-bdda-7d11c2a710eb.png', '9745f486-b55a-436d-b387-9ae738ab7d20.png', '3527'),
       ('Unknown.png', '2025/09/29/ce60db51-01e3-4484-bdda-7d11c2a710eb.png', '9745f486-b55a-436d-b387-9ae738ab7d20.png', '3527'),
       ('Unknown.png', '2025/09/29/ce60db51-01e3-4484-bdda-7d11c2a710eb.png', '9745f486-b55a-436d-b387-9ae738ab7d20.png', '3527'),
       ('Unknown.png', '2025/09/29/ce60db51-01e3-4484-bdda-7d11c2a710eb.png', '9745f486-b55a-436d-b387-9ae738ab7d20.png', '3527'),
       ('Unknown.png', '2025/09/29/ce60db51-01e3-4484-bdda-7d11c2a710eb.png', '9745f486-b55a-436d-b387-9ae738ab7d20.png', '3527'),
       ('Unknown.png', '2025/09/29/ce60db51-01e3-4484-bdda-7d11c2a710eb.png', '9745f486-b55a-436d-b387-9ae738ab7d20.png', '3527');

INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (57, 53, 'main'),
       (58, 54, 'main'),
       (59, 55, 'main'),
       (60, 56, 'main'),
       (61, 57, 'main'),
       (62, 58, 'main'),
       (63, 59, 'main'),
       (64, 60, 'main'),
       (65, 61, 'main');

-- 2
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 2', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-02', '2025-01-11', 3, 2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (2, 'public', 1, 0, 2);
INSERT INTO tbl_like (post_id, member_id)
VALUES (2, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 2', 2);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png', '/images/diary2.png', 'diary2_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (2, 2, 'main');

-- 3
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 3', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-03', '2025-01-12', 4, 3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (3, 'public', 1, 0, 3);
INSERT INTO tbl_like (post_id, member_id)
VALUES (3, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 3', 3);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png', '/images/diary3.png', 'diary3_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (3, 3, 'main');

-- 4
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 4', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-04', '2025-01-13', 5, 4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (4, 'public', 1, 0, 4);
INSERT INTO tbl_like (post_id, member_id)
VALUES (4, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 4', 4);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png', '/images/diary4.png', 'diary4_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (4, 4, 'main');

-- 5
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 5', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-05', '2025-01-14', 6, 5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (5, 'public', 1, 0, 5);
INSERT INTO tbl_like (post_id, member_id)
VALUES (5, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 5', 5);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png', '/images/diary5.png', 'diary5_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (5, 5, 'main');

-- 6
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 6', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-06', '2025-01-15', 2, 1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (6, 'public', 1, 0, 6);
INSERT INTO tbl_like (post_id, member_id)
VALUES (6, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 6', 6);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png', '/images/diary1.png', 'diary1_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (6, 6, 'main');

-- 7
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 7', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-07', '2025-01-16', 3, 2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (7, 'public', 1, 0, 7);
INSERT INTO tbl_like (post_id, member_id)
VALUES (7, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 7', 7);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png', '/images/diary2.png', 'diary2_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (7, 7, 'main');

-- 8
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 8', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-08', '2025-01-17', 4, 3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (8, 'public', 1, 0, 8);
INSERT INTO tbl_like (post_id, member_id)
VALUES (8, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 8', 8);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png', '/images/diary3.png', 'diary3_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (8, 8, 'main');

-- 9
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 9', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-09', '2025-01-18', 5, 4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (9, 'public', 1, 0, 9);
INSERT INTO tbl_like (post_id, member_id)
VALUES (9, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 9', 9);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png', '/images/diary4.png', 'diary4_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (9, 9, 'main');

-- 10
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 10', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-10', '2025-01-19', 6, 5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (10, 'public', 1, 0, 10);
INSERT INTO tbl_like (post_id, member_id)
VALUES (10, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 10', 10);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png', '/images/diary5.png', 'diary5_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (10, 10, 'main');

-- 11
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 11', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-11', '2025-01-20', 2, 1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (11, 'public', 1, 0, 11);
INSERT INTO tbl_like (post_id, member_id)
VALUES (11, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 11', 11);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png', '/images/diary1.png', 'diary1_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (11, 11, 'main');

-- 12
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 12', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-12', '2025-01-21', 3, 2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (12, 'public', 1, 0, 12);
INSERT INTO tbl_like (post_id, member_id)
VALUES (12, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 12', 12);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png', '/images/diary2.png', 'diary2_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (12, 12, 'main');

-- 13
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 13', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-13', '2025-01-22', 4, 3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (13, 'public', 1, 0, 13);
INSERT INTO tbl_like (post_id, member_id)
VALUES (13, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 13', 13);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png', '/images/diary3.png', 'diary3_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (13, 13, 'main');

-- 14
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 14', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-14', '2025-01-23', 5, 4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (14, 'public', 1, 0, 14);
INSERT INTO tbl_like (post_id, member_id)
VALUES (14, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 14', 14);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png', '/images/diary4.png', 'diary4_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (14, 14, 'main');

-- 15
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 15', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-15', '2025-01-24', 6, 5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (15, 'public', 1, 0, 15);
INSERT INTO tbl_like (post_id, member_id)
VALUES (15, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 15', 15);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png', '/images/diary5.png', 'diary5_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (15, 15, 'main');

-- 16
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 16', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-16', '2025-01-25', 2, 1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (16, 'public', 1, 0, 16);
INSERT INTO tbl_like (post_id, member_id)
VALUES (16, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 16', 16);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png', '/images/diary1.png', 'diary1_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (16, 16, 'main');

-- 17
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 17', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-17', '2025-01-26', 3, 2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (17, 'public', 1, 0, 17);
INSERT INTO tbl_like (post_id, member_id)
VALUES (17, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 17', 17);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png', '/images/diary2.png', 'diary2_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (17, 17, 'main');

-- 18
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 18', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-18', '2025-01-27', 4, 3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (18, 'public', 1, 0, 18);
INSERT INTO tbl_like (post_id, member_id)
VALUES (18, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 18', 18);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png', '/images/diary3.png', 'diary3_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (18, 18, 'main');

-- 19
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 19', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-19', '2025-01-28', 5, 4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (19, 'public', 1, 0, 19);
INSERT INTO tbl_like (post_id, member_id)
VALUES (19, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 19', 19);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png', '/images/diary4.png', 'diary4_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (19, 19, 'main');

-- 20
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 20', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-20', '2025-01-29', 6, 5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (20, 'public', 1, 0, 20);
INSERT INTO tbl_like (post_id, member_id)
VALUES (20, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 20', 20);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png', '/images/diary5.png', 'diary5_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (20, 20, 'main');

-- 21
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 21', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-21', '2025-01-30', 2, 1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (21, 'public', 1, 0, 21);
INSERT INTO tbl_like (post_id, member_id)
VALUES (21, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 21', 21);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png', '/images/diary1.png', 'diary1_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (21, 21, 'main');

-- 22
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 22', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-22', '2025-01-31', 3, 2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (22, 'public', 1, 0, 22);
INSERT INTO tbl_like (post_id, member_id)
VALUES (22, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 22', 22);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png', '/images/diary2.png', 'diary2_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (22, 22, 'main');

-- 23
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 23', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-23', '2025-01-32', 4, 3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (23, 'public', 1, 0, 23);
INSERT INTO tbl_like (post_id, member_id)
VALUES (23, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 23', 23);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png', '/images/diary3.png', 'diary3_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (23, 23, 'main');

-- 24
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 24', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-24', '2025-01-33', 5, 4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (24, 'public', 1, 0, 24);
INSERT INTO tbl_like (post_id, member_id)
VALUES (24, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 24', 24);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png', '/images/diary4.png', 'diary4_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (24, 24, 'main');

-- 25
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 25', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-25', '2025-01-34', 6, 5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (25, 'public', 1, 0, 25);
INSERT INTO tbl_like (post_id, member_id)
VALUES (25, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 25', 25);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png', '/images/diary5.png', 'diary5_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (25, 25, 'main');

-- 26
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 26', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-26', '2025-01-35', 2, 1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (26, 'public', 1, 0, 26);
INSERT INTO tbl_like (post_id, member_id)
VALUES (26, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 26', 26);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png', '/images/diary1.png', 'diary1_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (26, 26, 'main');

-- 27
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 27', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-27', '2025-01-36', 3, 2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (27, 'public', 1, 0, 27);
INSERT INTO tbl_like (post_id, member_id)
VALUES (27, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 27', 27);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png', '/images/diary2.png', 'diary2_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (27, 27, 'main');

-- 28
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 28', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-28', '2025-01-37', 4, 3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (28, 'public', 1, 0, 28);
INSERT INTO tbl_like (post_id, member_id)
VALUES (28, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 28', 28);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png', '/images/diary3.png', 'diary3_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (28, 28, 'main');

-- 29
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 29', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-29', '2025-01-38', 5, 4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (29, 'public', 1, 0, 29);
INSERT INTO tbl_like (post_id, member_id)
VALUES (29, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 29', 29);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png', '/images/diary4.png', 'diary4_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (29, 29, 'main');

-- 30
INSERT INTO tbl_post (post_title, member_id)
VALUES ('Diary Post 30', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-30', '2025-01-39', 6, 5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (30, 'public', 1, 0, 30);
INSERT INTO tbl_like (post_id, member_id)
VALUES (30, 1);
INSERT INTO tbl_post_section (post_content, post_id)
VALUES ('Diary content 30', 30);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png', '/images/diary5.png', 'diary5_20240926.png', '2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
VALUES (30, 30, 'main');

-- tbl_reply 더미 데이터
INSERT INTO tbl_reply (reply_content, diary_id, member_id)
VALUES ('좋은 글이네요!', 1, 3),
       ('여행기 재미있게 봤습니다.', 1, 4),
       ('사진이 멋져요!', 2, 5),
       ('가보고 싶네요~', 2, 6),
       ('공감합니다!', 3, 2),
       ('다음 글도 기대할게요.', 3, 5),
       ('풍경이 인상적이에요.', 4, 6),
       ('즐거운 여행 같아요!', 4, 1),
       ('좋은 정보 감사합니다.', 5, 2),
       ('재밌게 읽었어요 ^^', 5, 3),

       ('다음엔 저도 가보고 싶네요.', 6, 4),
       ('추억이 느껴지네요.', 7, 5),
       ('사진 퀄리티가 좋네요!', 7, 2),
       ('글이 따뜻하네요.', 8, 1),
       ('정말 멋진 경험 같아요!', 8, 6),
       ('여행 코스 참고하겠습니다.', 9, 3),
       ('읽으면서 힐링했어요.', 10, 4),
       ('좋은 글 감사합니다.', 10, 2),
       ('나도 그곳 다녀왔었는데 반갑네요.', 11, 5),
       ('추천 감사합니다!', 12, 6);



INSERT INTO tbl_crew (crew_name, crew_description)
values ('shake','크루 소개글 입니다 안녕하세요');

insert into tbl_crew_member(crew_role, crew_id, member_id)
values ('leader',1,1);

insert into tbl_crew_diary(crew_id, diary_id)
values (1,29);

INSERT INTO tbl_country(country_name)
values ('프랑스');

INSERT INTO tbl_country(country_name)
VALUES ('가나'),
       ('가봉'),
       ('가이아나'),
       ('감비아'),
       ('과테말라'),
       ('그레나다'),
       ('그리스'),
       ('기니'),
       ('기니비사우'),
       ('나미비아'),
       ('나우루'),
       ('나이지리아'),
       ('남수단'),
       ('남아프리카공화국'),
       ('네덜란드'),
       ('네팔'),
       ('노르웨이'),
       ('뉴질랜드'),
       ('니카라과'),
       ('니제르'),
       ('덴마크'),
       ('도미니카공화국'),
       ('도미니카연방'),
       ('독일'),
       ('동티모르'),
       ('라오스'),
       ('라이베리아'),
       ('라트비아'),
       ('러시아'),
       ('레바논'),
       ('레소토'),
       ('루마니아'),
       ('룩셈부르크'),
       ('르완다'),
       ('리비아'),
       ('리투아니아'),
       ('리히텐슈타인'),
       ('마다가스카르'),
       ('마셜제도'),
       ('말라위'),
       ('말레이시아'),
       ('말리'),
       ('멕시코'),
       ('모나코'),
       ('모로코'),
       ('모리셔스'),
       ('모리타니'),
       ('모잠비크'),
       ('몬테네그로'),
       ('몰도바'),
       ('몰디브'),
       ('몰타'),
       ('몽골'),
       ('미얀마'),
       ('미크로네시아'),
       ('바누아투'),
       ('바레인'),
       ('바베이도스'),
       ('바하마'),
       ('방글라데시'),
       ('베냉'),
       ('베네수엘라'),
       ('베트남'),
       ('벨기에'),
       ('벨라루스'),
       ('벨리즈'),
       ('보스니아헤르체고비나'),
       ('보츠와나'),
       ('볼리비아'),
       ('부룬디'),
       ('부르키나파소'),
       ('부탄'),
       ('북마케도니아'),
       ('북한'),
       ('불가리아'),
       ('브라질'),
       ('브루나이'),
       ('사모아'),
       ('사우디아라비아'),
       ('사이프러스'),
       ('산마리노'),
       ('상투메프린시페'),
       ('세네갈'),
       ('세르비아'),
       ('세이셸'),
       ('세인트루시아'),
       ('세인트빈센트그레나딘'),
       ('세인트키츠네비스'),
       ('소말리아'),
       ('솔로몬제도'),
       ('수단'),
       ('수리남'),
       ('스리랑카'),
       ('스웨덴'),
       ('스위스'),
       ('스페인'),
       ('슬로바키아'),
       ('슬로베니아'),
       ('시리아'),
       ('시에라리온'),
       ('싱가포르'),
       ('아랍에미리트'),
       ('아르메니아'),
       ('아르헨티나'),
       ('아이슬란드'),
       ('아이티'),
       ('아일랜드'),
       ('아제르바이잔'),
       ('아프가니스탄'),
       ('안도라'),
       ('알바니아'),
       ('알제리'),
       ('앙골라'),
       ('앤티가바부다'),
       ('에콰도르'),
       ('에스와티니'),
       ('에스토니아'),
       ('에티오피아'),
       ('엘살바도르'),
       ('영국'),
       ('예멘'),
       ('오만'),
       ('오스트리아'),
       ('온두라스'),
       ('요르단'),
       ('우간다'),
       ('우루과이'),
       ('우즈베키스탄'),
       ('우크라이나'),
       ('이라크'),
       ('이란'),
       ('이스라엘'),
       ('이집트'),
       ('인도'),
       ('인도네시아'),
       ('잠비아'),
       ('적도기니'),
       ('조지아'),
       ('중앙아프리카공화국'),
       ('중국'),
       ('지부티'),
       ('짐바브웨'),
       ('체코'),
       ('칠레'),
       ('카메룬'),
       ('카보베르데'),
       ('카자흐스탄'),
       ('카타르'),
       ('캄보디아'),
       ('캐나다'),
       ('케냐'),
       ('코모로'),
       ('코스타리카'),
       ('코트디부아르'),
       ('콜롬비아'),
       ('콩고공화국'),
       ('콩고민주공화국'),
       ('쿠바'),
       ('쿠웨이트'),
       ('쿡제도'),
       ('크로아티아'),
       ('키르기스스탄'),
       ('키리바시'),
       ('타지키스탄'),
       ('탄자니아'),
       ('태국'),
       ('토고'),
       ('통가'),
       ('투르크메니스탄'),
       ('투발루'),
       ('튀니지'),
       ('튀르키예'),
       ('트리니다드토바고'),
       ('파나마'),
       ('파라과이'),
       ('파키스탄'),
       ('파푸아뉴기니'),
       ('팔라우'),
       ('팔레스타인'),
       ('페루'),
       ('포르투갈'),
       ('폴란드'),
       ('피지'),
       ('핀란드'),
       ('필리핀');


select vpp.id as post_id,
       vpp.post_title,
       vpp.purchase_country,
       vpp.purchase_delivery_method,
       vpp.purchase_limit_time,
       vpp.purchase_product_count,
       vpp.purchase_product_price as price,
       vpp.purchase_delivery_method,
       vpp.created_datetime,
       vpp.updated_datetime,
       tm.id as member_id,
       tm.chemistry_score,
       tm.member_name,
       tm.social_img_url,
       vfmf.id as file_id,
       vfmf.file_name,
       vfmf.file_origin_name,
       vfmf.file_path,
       ta.address,
       vpp.created_datetime + (vpp.purchase_limit_time || 'hour')::interval > now()
from tbl_member tm
         left outer join view_file_member_file vfmf on tm.id = vfmf.member_id
         join view_post_purchase vpp on tm.id = vpp.member_id and vpp.id = 1
    join tbl_address ta on tm.id = ta.member_id
-- where vpp.post_status = 'active' and vpp.created_datetime + (vpp.purchase_limit_time || 'hour')::interval > now();
-- select now();