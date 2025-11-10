EXPLAIN ANALYZE
select vpp.post_title,
       vpp.purchase_country,
       vpp.purchase_delivery_method,
       vpp.purchase_limit_time,
       vpp.purchase_product_count,
       vpp.purchase_product_price,
       vpp.purchase_delivery_method,
       vpp.created_datetime,
       vpp.updated_datetime,
       tm.id,
       tm.chemistry_score,
       tm.member_name,
       tm.social_img_url,
       vfmf.id as file_id,
       vfmf.file_name,
       vfmf.file_origin_name,
       vfmf.file_path,
       ta.address
from tbl_member tm
         left outer join view_file_member_file vfmf on tm.id = vfmf.member_id
         join view_post_purchase vpp on tm.id = vpp.member_id and vpp.id = 1
         join tbl_address ta on tm.id = ta.member_id;



EXPLAIN ANALYZE
select *
from tbl_member tm
         left outer join view_file_member_file vfmf on tm.id = vfmf.member_id
         join view_post_purchase vpp on tm.id = vpp.member_id
         join tbl_address ta on tm.id = ta.member_id;


EXPLAIN ANALYZE
select vpp.id as post_id,
       vpp.post_title,
       vpp.purchase_country,
       vpp.purchase_delivery_method,
       vpp.purchase_limit_time,
       vpp.purchase_product_count,
       vpp.purchase_product_price,
       vpp.purchase_delivery_method,
       vpp.created_datetime,
       vpp.updated_datetime,
       vfps.file_path,
       vfps.file_name,
       tm.member_name,
       tm.chemistry_score
from tbl_member tm join
     view_post_purchase vpp on tm.id = vpp.member_id
                   join tbl_post_section tps on vpp.id = tps.post_id and vpp.post_status = 'active'
                   join view_file_post_section_file vfps on tps.id = vfps.post_section_id and vfps.image_type = 'main'
-- where vpp.created_datetime + (vpp.purchase_limit_time || 'hour')::interval > now()
--   and (
where vpp.purchase_country like '%' || 'test' || '%'
   or vpp.post_title like '%' || 'test' || '%'
--     )
limit 5 offset 0;

create extension if not exists pg_trgm;/* (최초 1번만)*/
create index idx_member_name_trgm
    on tbl_post
        using gin (post_title gin_trgm_ops);

create index idx_member_test_trgm
    on tbl_purchase
        using gin (purchase_country gin_trgm_ops);







select vpp.id as post_id,
       vpp.post_title,
       vpp.purchase_country,
       vpp.purchase_delivery_method,
       vpp.purchase_limit_time,
       vpp.purchase_product_count,
       vpp.purchase_product_price,
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
       ta.address
from tbl_member tm
         left outer join view_file_member_file vfmf on tm.id = vfmf.member_id
         join view_post_purchase vpp on tm.id = vpp.member_id and vpp.id = 3
         join tbl_address ta on tm.id = ta.member_id
where vpp.post_status = 'active'

select * from view_post_purchase;


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

Select * from tbl_member;
Select * from tbl_like;

UPDATE tbl_member
SET member_name = '데구르르구르는바나나'
WHERE id = 3;

-- 2. 회원
INSERT INTO tbl_member (member_name, member_email, member_password, social_img_url) VALUES
                                                                                        ('Alice', 'alice@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Alice'),
                                                                                        ('Bob', 'bob@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Bob'),
                                                                                        ('Charlie', 'charlie@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Charlie'),
                                                                                        ('David', 'david@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=David'),
                                                                                        ('Emma', 'emma@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Emma'),
                                                                                        ('Frank', 'frank@test.com', 'pass123', 'https://dummyimage.com/100x100/000/fff&text=Frank');

-- 3. 나라
INSERT INTO tbl_country (country_name) VALUES
                                           ('Korea'), ('Japan'), ('USA'), ('France'), ('Italy');

-- 4. 일기 더미 데이터 (30개)

-- 1
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 1', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-01','2025-01-10',2,1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (1,'public',1,0,1);
INSERT INTO tbl_like (post_id, member_id) VALUES (1,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 1',1);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png','/images/diary1.png','diary1_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (1,1,'main');

-- 2
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 2', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-02','2025-01-11',3,2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (2,'public',1,0,2);
INSERT INTO tbl_like (post_id, member_id) VALUES (2,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 2',2);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png','/images/diary2.png','diary2_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (2,2,'main');

-- 3
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 3', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-03','2025-01-12',4,3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (3,'public',1,0,3);
INSERT INTO tbl_like (post_id, member_id) VALUES (3,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 3',3);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png','/images/diary3.png','diary3_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (3,3,'main');

-- 4
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 4', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-04','2025-01-13',5,4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (4,'public',1,0,4);
INSERT INTO tbl_like (post_id, member_id) VALUES (4,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 4',4);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png','/images/diary4.png','diary4_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (4,4,'main');

-- 5
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 5', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-05','2025-01-14',6,5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (5,'public',1,0,5);
INSERT INTO tbl_like (post_id, member_id) VALUES (5,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 5',5);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png','/images/diary5.png','diary5_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (5,5,'main');

-- 6
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 6', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-06','2025-01-15',2,1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (6,'public',1,0,6);
INSERT INTO tbl_like (post_id, member_id) VALUES (6,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 6',6);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png','/images/diary1.png','diary1_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (6,6,'main');

-- 7
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 7', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-07','2025-01-16',3,2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (7,'public',1,0,7);
INSERT INTO tbl_like (post_id, member_id) VALUES (7,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 7',7);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png','/images/diary2.png','diary2_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (7,7,'main');

-- 8
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 8', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-08','2025-01-17',4,3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (8,'public',1,0,8);
INSERT INTO tbl_like (post_id, member_id) VALUES (8,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 8',8);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png','/images/diary3.png','diary3_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (8,8,'main');

-- 9
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 9', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-09','2025-01-18',5,4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (9,'public',1,0,9);
INSERT INTO tbl_like (post_id, member_id) VALUES (9,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 9',9);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png','/images/diary4.png','diary4_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (9,9,'main');

-- 10
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 10', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-10','2025-01-19',6,5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (10,'public',1,0,10);
INSERT INTO tbl_like (post_id, member_id) VALUES (10,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 10',10);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png','/images/diary5.png','diary5_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (10,10,'main');

-- 11
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 11', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-11','2025-01-20',2,1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (11,'public',1,0,11);
INSERT INTO tbl_like (post_id, member_id) VALUES (11,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 11',11);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png','/images/diary1.png','diary1_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (11,11,'main');

-- 12
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 12', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-12','2025-01-21',3,2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (12,'public',1,0,12);
INSERT INTO tbl_like (post_id, member_id) VALUES (12,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 12',12);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png','/images/diary2.png','diary2_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (12,12,'main');

-- 13
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 13', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-13','2025-01-22',4,3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (13,'public',1,0,13);
INSERT INTO tbl_like (post_id, member_id) VALUES (13,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 13',13);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png','/images/diary3.png','diary3_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (13,13,'main');

-- 14
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 14', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-14','2025-01-23',5,4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (14,'public',1,0,14);
INSERT INTO tbl_like (post_id, member_id) VALUES (14,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 14',14);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png','/images/diary4.png','diary4_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (14,14,'main');

-- 15
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 15', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-15','2025-01-24',6,5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (15,'public',1,0,15);
INSERT INTO tbl_like (post_id, member_id) VALUES (15,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 15',15);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png','/images/diary5.png','diary5_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (15,15,'main');

-- 16
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 16', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-16','2025-01-25',2,1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (16,'public',1,0,16);
INSERT INTO tbl_like (post_id, member_id) VALUES (16,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 16',16);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png','/images/diary1.png','diary1_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (16,16,'main');

-- 17
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 17', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-17','2025-01-26',3,2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (17,'public',1,0,17);
INSERT INTO tbl_like (post_id, member_id) VALUES (17,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 17',17);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png','/images/diary2.png','diary2_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (17,17,'main');

-- 18
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 18', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-18','2025-01-27',4,3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (18,'public',1,0,18);
INSERT INTO tbl_like (post_id, member_id) VALUES (18,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 18',18);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png','/images/diary3.png','diary3_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (18,18,'main');

-- 19
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 19', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-19','2025-01-28',5,4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (19,'public',1,0,19);
INSERT INTO tbl_like (post_id, member_id) VALUES (19,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 19',19);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png','/images/diary4.png','diary4_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (19,19,'main');

-- 20
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 20', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-20','2025-01-29',6,5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (20,'public',1,0,20);
INSERT INTO tbl_like (post_id, member_id) VALUES (20,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 20',20);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png','/images/diary5.png','diary5_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (20,20,'main');

-- 21
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 21', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-21','2025-01-30',2,1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (21,'public',1,0,21);
INSERT INTO tbl_like (post_id, member_id) VALUES (21,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 21',21);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png','/images/diary1.png','diary1_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (21,21,'main');

-- 22
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 22', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-22','2025-01-31',3,2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (22,'public',1,0,22);
INSERT INTO tbl_like (post_id, member_id) VALUES (22,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 22',22);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png','/images/diary2.png','diary2_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (22,22,'main');

-- 23
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 23', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-23','2025-01-32',4,3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (23,'public',1,0,23);
INSERT INTO tbl_like (post_id, member_id) VALUES (23,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 23',23);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png','/images/diary3.png','diary3_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (23,23,'main');

-- 24
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 24', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-24','2025-01-33',5,4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (24,'public',1,0,24);
INSERT INTO tbl_like (post_id, member_id) VALUES (24,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 24',24);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png','/images/diary4.png','diary4_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (24,24,'main');

-- 25
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 25', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-25','2025-01-34',6,5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (25,'public',1,0,25);
INSERT INTO tbl_like (post_id, member_id) VALUES (25,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 25',25);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png','/images/diary5.png','diary5_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (25,25,'main');

-- 26
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 26', 2);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-26','2025-01-35',2,1);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (26,'public',1,0,26);
INSERT INTO tbl_like (post_id, member_id) VALUES (26,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 26',26);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary1.png','/images/diary1.png','diary1_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (26,26,'main');

-- 27
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 27', 3);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-27','2025-01-36',3,2);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (27,'public',1,0,27);
INSERT INTO tbl_like (post_id, member_id) VALUES (27,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 27',27);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary2.png','/images/diary2.png','diary2_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (27,27,'main');

-- 28
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 28', 4);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-28','2025-01-37',4,3);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (28,'public',1,0,28);
INSERT INTO tbl_like (post_id, member_id) VALUES (28,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 28',28);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary3.png','/images/diary3.png','diary3_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (28,28,'main');

-- 29
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 29', 5);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-29','2025-01-38',5,4);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (29,'public',1,0,29);
INSERT INTO tbl_like (post_id, member_id) VALUES (29,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 29',29);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary4.png','/images/diary4.png','diary4_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (29,29,'main');

-- 30
INSERT INTO tbl_post (post_title, member_id) VALUES ('Diary Post 30', 6);
INSERT INTO tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
VALUES ('2025-01-30','2025-01-39',6,5);
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (30,'public',1,0,30);
INSERT INTO tbl_like (post_id, member_id) VALUES (30,1);
INSERT INTO tbl_post_section (post_content, post_id) VALUES ('Diary content 30',30);
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES ('diary5.png','/images/diary5.png','diary5_20240926.png','2048');
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type) VALUES (30,30,'main');

-- tbl_reply 더미 데이터
INSERT INTO tbl_reply (reply_content, diary_id, member_id) VALUES
                                                               ('좋은 글이네요!', 1, 3),
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


-- 1) 크루 3개
INSERT INTO tbl_crew (crew_name, crew_description, crew_member_count)
VALUES
    ('오사카 크루', '오사카 여행 같이 가는 사람들', 2),
    ('뉴욕 크루', '뉴욕 브런치 투어 크루', 3),
    ('파리 크루', '파리 미술관 투어 크루', 2);

-- 2) 크루 파일 (크루 썸네일 이미지)
--   tbl_file 에 crew1.png, crew2.png, crew3.png 가 있다고 가정
INSERT INTO tbl_crew_file (file_id, crew_id)
SELECT f.id, c.id
FROM tbl_file f
         JOIN tbl_crew c ON c.crew_name='오사카 크루'
WHERE f.file_name='crew1.png';

INSERT INTO tbl_crew_file (file_id, crew_id)
SELECT f.id, c.id
FROM tbl_file f
         JOIN tbl_crew c ON c.crew_name='뉴욕 크루'
WHERE f.file_name='crew2.png';

INSERT INTO tbl_crew_file (file_id, crew_id)
SELECT f.id, c.id
FROM tbl_file f
         JOIN tbl_crew c ON c.crew_name='파리 크루'
WHERE f.file_name='crew3.png';

-- 3) 크루 멤버
--   멤버 3명 (alice, bob, carol)이 있다고 가정
INSERT INTO tbl_crew_member (crew_role, crew_id, member_id)
VALUES
    ('leader'::crew_role,
     (SELECT id FROM tbl_crew WHERE crew_name='오사카 크루'),
     (SELECT id FROM tbl_member WHERE member_email='alice@example.com')),
    ('partner'::crew_role,
     (SELECT id FROM tbl_crew WHERE crew_name='오사카 크루'),
     (SELECT id FROM tbl_member WHERE member_email='bob@example.com')),

    ('leader'::crew_role,
     (SELECT id FROM tbl_crew WHERE crew_name='뉴욕 크루'),
     (SELECT id FROM tbl_member WHERE member_email='carol@example.com')),
    ('partner'::crew_role,
     (SELECT id FROM tbl_crew WHERE crew_name='뉴욕 크루'),
     (SELECT id FROM tbl_member WHERE member_email='alice@example.com')),
    ('partner'::crew_role,
     (SELECT id FROM tbl_crew WHERE crew_name='뉴욕 크루'),
     (SELECT id FROM tbl_member WHERE member_email='bob@example.com')),

    ('leader'::crew_role,
     (SELECT id FROM tbl_crew WHERE crew_name='파리 크루'),
     (SELECT id FROM tbl_member WHERE member_email='carol@example.com')),
    ('partner'::crew_role,
     (SELECT id FROM tbl_crew WHERE crew_name='파리 크루'),
     (SELECT id FROM tbl_member WHERE member_email='alice@example.com'));


-------------------------

-- 혹시 실패 트랜잭션 잔여가 있으면 먼저
ROLLBACK;

BEGIN;

-- 1) 크루 썸네일 파일 3개 (없다면 생성)
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
VALUES
    ('osaka_crew.png','images/crew/','osaka_crew.png','1024'),
    ('ny_crew.png',   'images/crew/','ny_crew.png','1024'),
    ('paris_crew.png','images/crew/','paris_crew.png','1024');

-- 2) 크루 3개
INSERT INTO tbl_crew (crew_name, crew_description, crew_member_count)
VALUES
    ('오사카 크루',  '오사카 여행 같이 가는 사람들', 2),
    ('뉴욕 크루',    '뉴욕 브런치/산책 모임',       3),
    ('파리 크루',    '파리 미술관/산책 모임',       2);


-- 1) 깨진 트랜잭션 해제
ROLLBACK;

BEGIN;

-- 2) 크루 썸네일 파일이 없으면 만들기 (있으면 건너뜀)
INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
SELECT 'osaka_crew.png','images/crew/','osaka_crew.png','1024'
WHERE NOT EXISTS (SELECT 1 FROM tbl_file WHERE file_name='osaka_crew.png');

INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
SELECT 'ny_crew.png','images/crew/','ny_crew.png','1024'
WHERE NOT EXISTS (SELECT 1 FROM tbl_file WHERE file_name='ny_crew.png');

INSERT INTO tbl_file (file_origin_name, file_path, file_name, file_size)
SELECT 'paris_crew.png','images/crew/','paris_crew.png','1024'
WHERE NOT EXISTS (SELECT 1 FROM tbl_file WHERE file_name='paris_crew.png');

-- 3) 크루가 없으면 만들기 (있으면 건너뜀)
INSERT INTO tbl_crew (crew_name, crew_description, crew_member_count)
SELECT '오사카 크루','오사카 여행 같이 가는 사람들',2
WHERE NOT EXISTS (SELECT 1 FROM tbl_crew WHERE crew_name='오사카 크루');

INSERT INTO tbl_crew (crew_name, crew_description, crew_member_count)
SELECT '뉴욕 크루','뉴욕 브런치/산책 모임',3
WHERE NOT EXISTS (SELECT 1 FROM tbl_crew WHERE crew_name='뉴욕 크루');

INSERT INTO tbl_crew (crew_name, crew_description, crew_member_count)
SELECT '파리 크루','파리 미술관/산책 모임',2
WHERE NOT EXISTS (SELECT 1 FROM tbl_crew WHERE crew_name='파리 크루');

-- 4) 크루–파일 매핑: 중복이면 crew_id 만 업데이트 (UPSERT)
INSERT INTO tbl_crew_file (file_id, crew_id)
SELECT f.id, c.id
FROM tbl_file f JOIN tbl_crew c ON c.crew_name='오사카 크루'
WHERE f.file_name='osaka_crew.png'
ON CONFLICT (file_id) DO UPDATE SET crew_id = EXCLUDED.crew_id;

INSERT INTO tbl_crew_file (file_id, crew_id)
SELECT f.id, c.id
FROM tbl_file f JOIN tbl_crew c ON c.crew_name='뉴욕 크루'
WHERE f.file_name='ny_crew.png'
ON CONFLICT (file_id) DO UPDATE SET crew_id = EXCLUDED.crew_id;

INSERT INTO tbl_crew_file (file_id, crew_id)
SELECT f.id, c.id
FROM tbl_file f JOIN tbl_crew c ON c.crew_name='파리 크루'
WHERE f.file_name='paris_crew.png'
ON CONFLICT (file_id) DO UPDATE SET crew_id = EXCLUDED.crew_id;

-- 5) 크루 멤버 배정 (멤버가 있으면만 들어가게)
-- 오사카: Alice(leader), Bob(partner)
INSERT INTO tbl_crew_member (crew_role, crew_id, member_id)
SELECT 'leader'::crew_role, c.id, m.id
FROM tbl_crew c JOIN tbl_member m ON m.member_name='Alice'
WHERE c.crew_name='오사카 크루'
  AND NOT EXISTS (
    SELECT 1 FROM tbl_crew_member x
    WHERE x.crew_id = c.id AND x.member_id = m.id
);

INSERT INTO tbl_crew_member (crew_role, crew_id, member_id)
SELECT 'partner'::crew_role, c.id, m.id
FROM tbl_crew c JOIN tbl_member m ON m.member_name='Bob'
WHERE c.crew_name='오사카 크루'
  AND NOT EXISTS (
    SELECT 1 FROM tbl_crew_member x
    WHERE x.crew_id = c.id AND x.member_id = m.id
);

-- 뉴욕: Charlie(leader), Emma(partner), Frank(partner)
INSERT INTO tbl_crew_member (crew_role, crew_id, member_id)
SELECT 'leader'::crew_role, c.id, m.id
FROM tbl_crew c JOIN tbl_member m ON m.member_name='Charlie'
WHERE c.crew_name='뉴욕 크루'
  AND NOT EXISTS (SELECT 1 FROM tbl_crew_member x WHERE x.crew_id=c.id AND x.member_id=m.id);

INSERT INTO tbl_crew_member (crew_role, crew_id, member_id)
SELECT 'partner'::crew_role, c.id, m.id
FROM tbl_crew c JOIN tbl_member m ON m.member_name='Emma'
WHERE c.crew_name='뉴욕 크루'
  AND NOT EXISTS (SELECT 1 FROM tbl_crew_member x WHERE x.crew_id=c.id AND x.member_id=m.id);

INSERT INTO tbl_crew_member (crew_role, crew_id, member_id)
SELECT 'partner'::crew_role, c.id, m.id
FROM tbl_crew c JOIN tbl_member m ON m.member_name='Frank'
WHERE c.crew_name='뉴욕 크루'
  AND NOT EXISTS (SELECT 1 FROM tbl_crew_member x WHERE x.crew_id=c.id AND x.member_id=m.id);

-- 파리: Alice(leader), Charlie(partner)
INSERT INTO tbl_crew_member (crew_role, crew_id, member_id)
SELECT 'leader'::crew_role, c.id, m.id
FROM tbl_crew c JOIN tbl_member m ON m.member_name='Alice'
WHERE c.crew_name='파리 크루'
  AND NOT EXISTS (SELECT 1 FROM tbl_crew_member x WHERE x.crew_id=c.id AND x.member_id=m.id);

INSERT INTO tbl_crew_member (crew_role, crew_id, member_id)
SELECT 'partner'::crew_role, c.id, m.id
FROM tbl_crew c JOIN tbl_member m ON m.member_name='Charlie'
WHERE c.crew_name='파리 크루'
  AND NOT EXISTS (SELECT 1 FROM tbl_crew_member x WHERE x.crew_id=c.id AND x.member_id=m.id);

COMMIT;

-- 후보 post / crew / file / country_path 하나씩 확인
select id from tbl_post order by id desc limit 5;
select id from tbl_crew order by id desc limit 5;
select id, file_name, file_path from tbl_file order by id desc limit 5;

insert into tbl_country (country_name) values
                                           ('France'),
                                           ('USA'),
                                           ('Japan');

insert into tbl_diary_country_path (country_id)
values ( 1), (2), (3);

insert into tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
values
    (28, 'public', 12, 3, 1), -- 프랑스
    (27, 'public', 8, 1, 2),  -- 미국
    (26, 'public', 23, 5, 3); -- 일본

insert into tbl_crew_diary (crew_id, diary_id) values
                                                   (1, 28),
                                                   (2, 27),
                                                   (3, 26);


select id from tbl_post where id in (28,27,26);
select id from tbl_crew where id in (1,2,3);
select id, country_id from tbl_diary_country_path;

insert into tbl_diary_country_path (country_start_date, country_end_date, member_id, country_id)
values
    ('2025-09-01', '2025-09-10', 1, 1), -- France
    ('2025-10-05', '2025-10-12', 1, 2), -- USA
    ('2025-11-01', '2025-11-07', 1, 3); -- Japan

insert into tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
    overriding system value
values
    (28, 'public', 12, 3, 1),
    (27, 'public', 8, 1, 2),
    (26, 'public', 23, 5, 3);



insert into tbl_post_section_file (file_id, post_section_id, image_type)
values
    (24, 32, 'main'),  -- 파리 (post 28 → section 32 → file 24)
    (23, 33, 'main'),  -- 뉴욕 (post 27 → section 33 → file 23)
    (22, 34, 'main');  -- 오사카 (post 26 → section 34 → file 22)



-- 필요한 섹션 id들(예: 32,33,34)에 맞춰 더미 배너 생성
insert into tbl_banner (id, banner_order)
    overriding system value
values (32, 1), (33, 2), (34, 3);

select id from tbl_banner where id in (32,33,34);

-- 예시: post_section_id = 32,33,34 / file_id = 24,23,22 / 대표이미지 main
insert into tbl_post_section_file (file_id, post_section_id, image_type)
values
    (24, 32, 'main'),
    (23, 33, 'main'),
    (22, 34, 'main');

select ps.post_id, ps.id as post_section_id, psf.file_id, psf.image_type
from tbl_post_section ps
         join tbl_post_section_file psf on psf.post_section_id = ps.id
where ps.id in (32,33,34);


begin;

-- 0) 국가 (view에서 country 조인)
insert into tbl_country (id, country_name) overriding system value values
                                                                       (1, 'France'),
                                                                       (2, 'United States'),
                                                                       (3, 'Japan')
on conflict (id) do nothing;

-- 1) 멤버 (AccompanyMapper가 member 조인)
--    실제 컬럼 구성이 다를 수 있으니, 필요한 컬럼만 골라서 사용하세요.
insert into tbl_member (id, member_name, member_description, social_img_url)
    overriding system value
values
    (101, 'alice', '파리 좋아하는 멤버', 'https://dummyimage.com/100x100/000/fff&text=A'),
    (102, 'bob',   '뉴욕 좋아하는 멤버', 'https://dummyimage.com/100x100/000/fff&text=B'),
    (103, 'coco',  '오사카 좋아하는 멤버', 'https://dummyimage.com/100x100/000/fff&text=C'),
    (104, 'dave',  '서울 좋아하는 멤버', 'https://dummyimage.com/100x100/000/fff&text=D')
on conflict (id) do nothing;

-- 2) post (view의 뿌리. member_id 필수)
--    기본적으로 post_status='active'가 뷰에 걸려 있을 가능성이 높습니다.
insert into tbl_post (id, post_title, post_status, member_id)
    overriding system value
values
    (201, '파리 브런치 투어', 'active', 101),
    (202, '뉴욕 야경 동행',   'active', 102),
    (203, '오사카 미식 투어', 'active', 103),
    (204, '서울 베이커리 투어','active', 104)
on conflict (id) do nothing;

-- 3) accompany (post_id FK)
insert into tbl_accompany (post_id, accompany_status, accompany_age_range)
values
    (201, 'short', 20),
    (202, 'short', 25),
    (203, 'short', 30),
    (204, 'short', 22)
on conflict (post_id) do nothing;

-- 4) accompany_path (view에서 기간/국가 조인)
--    스키마가 보통: id(identity), accompany_id(FK to tbl_accompany.post_id), country_start_date, country_end_date, country_id
insert into tbl_accompany_path (accompany_id, country_start_date, country_end_date, country_id)
values
    (201, '2025-10-01', '2025-10-05', 1),  -- France
    (202, '2025-10-10', '2025-10-12', 2),  -- United States
    (203, '2025-10-15', '2025-10-20', 3),  -- Japan
    (204, '2025-10-22', '2025-10-23', 1)   -- France (예시)
on conflict do nothing;

-- 5) crew (AccompanyMapper에서 조인)
insert into tbl_crew (id, crew_name, crew_description, crew_member_count)
    overriding system value
values
    (1, '파리 크루', '파리 같이 가요', 3),
    (2, '뉴욕 크루', '뉴욕 같이 가요', 4),
    (3, '오사카 크루', '오사카 같이 가요', 2)
on conflict (id) do nothing;

-- 6) crew_member (멤버-크루 연결)
insert into tbl_crew_member (crew_id, member_id, crew_role)
values
    (1, 101, 'leader'),
    (2, 102, 'partner'),
    (3, 103, 'partner'),
    (1, 104, 'partner')
on conflict do nothing;

-- 7) file (크루 썸네일용. file_size NOT NULL 주의!)
insert into tbl_file (id, file_origin_name, file_path, file_name, file_size)
    overriding system value
values
    (301, 'paris_main.png',  '/images/accompany/paris_main.png',  'paris_main.png',  '12345'),
    (302, 'ny_main.png',     '/images/accompany/ny_main.png',     'ny_main.png',     '12345'),
    (303, 'osaka_main.png',  '/images/accompany/osaka_main.png',  'osaka_main.png',  '12345')
on conflict (id) do nothing;

-- 8) crew_file (크루-파일 연결)
insert into tbl_crew_file (file_id, crew_id)
values
    (301, 1),
    (302, 2),
    (303, 3)
on conflict (file_id) do nothing;

commit;

insert into tbl_post (post_title, post_read_count, post_status, member_id)
values ('테스트1','50','active','7');

insert into tbl_post_section(post_content, post_id)
values ('동행크루1 테스트','35');

insert into tbl_post_section_file(file_id, post_section_id, image_type)
values ('9', '9','main');

insert into tbl_file(file_origin_name, file_path, file_name, file_size)
values ('accompanytest4.png','2025/10/01/accompanytest4.png','accompanytest4.png',1000);

select * from tbl_post;

insert into tbl_accompany(post_id, accompany_status, accompany_age_range)
values ('35','short','20');

insert into tbl_accompany_path(country_start_date, country_end_date, accompany_id, country_id)
values (2025-10-01,'2025-10-05','35','5');

insert into tbl_crew (crew_name, crew_description, crew_member_count)
values ('불꽃크루','크루모집합니다1','3');

BEGIN;

-- 기본 12명 더미 (중복 메일 회피: ON CONFLICT DO NOTHING)
INSERT INTO tbl_member (
    member_name, member_phone, member_email,
    member_social_url, member_birth, member_gender, member_mbti,
    member_password, member_status, member_provider,
    social_img_url, member_social_email, member_description,
    member_role, chemistry_score
)

VALUES
('test3', '01011132003', 'fqjn@crewstation',
 'https://facebook.com/jiwoo', '19990421', 'female', 'ISTJ',
 'pw_hsh_3', 'active', 'google',
 'https://img.crewstation.dev/members/u03.png', 'jiwowqr.social@googlemail.com', '테스트', 'member', 72);

insert into tbl_diary (post_id,diary_secret,diary_like_count, diary_reply_count, diary_country_path_id)
values ('18','active',60,90,'10');

SELECT id, post_title FROM tbl_post WHERE id IN (26,27,28);
SELECT id FROM tbl_diary_country_path WHERE id IN (1,2,3);

SELECT
    d.post_id,
    p.post_title,
    d.diary_secret,
    d.diary_like_count,
    d.diary_reply_count,
    d.diary_country_path_id,
    c.country_name,
    dcp.country_start_date,
    dcp.country_end_date
FROM tbl_diary d
         JOIN tbl_post p
              ON p.id = d.post_id
         JOIN tbl_diary_country_path dcp
              ON dcp.id = d.diary_country_path_id
         JOIN tbl_country c
              ON c.id = dcp.country_id
WHERE d.post_id IN (26,27,28)
ORDER BY d.post_id DESC;


-- 파일 더미 데이터
insert into tbl_file (id, file_name, file_origin_name, file_path, created_datetime)
values (100, 'dummy.jpg', 'dummy.jpg', '/images/dummy.jpg', now());

-- 멤버 프로필 파일 매핑
insert into tbl_member_file (id, member_id, file_id)
values (1, 1, 100);

-- 다이어리 섹션 파일 매핑 (대표 이미지)
insert into tbl_post_section_file (post_section_id, file_id, image_type)
values ( 10, 100, 'main');

insert into tbl_post (member_id, post_title, post_status, post_read_count, created_datetime, updated_datetime)
values
    (1, 'Diary Post 19', 'active', 0, now(), now()),
    (1, 'Diary Post 20', 'active', 0, now(), now()),
    (1, 'Diary Post 21', 'active', 0, now(), now()),
    (1, 'Diary Post 22', 'active', 0, now(), now());

INSERT INTO tbl_post_section (post_id, post_content)
VALUES
    (19, '더미 본문 19 입니다.'),
    (20, '더미 본문 20 입니다.'),
    (21, '더미 본문 21 입니다.'),
    (22, '더미 본문 22 입니다.');

INSERT INTO tbl_file (file_name, file_origin_name, file_path, file_size, created_datetime, updated_datetime)
VALUES ('dummy-main.jpg', 'dummy-main.jpg', '/images/dummy-main.jpg', 1024, NOW(), NOW());

INSERT INTO tbl_file (file_name, file_origin_name, file_path, file_size, created_datetime, updated_datetime)
VALUES
    ('dummy-19.jpg','dummy-19.jpg','/images/dummy-19.jpg', 1024, NOW(), NOW()),
    ('dummy-20.jpg','dummy-20.jpg','/images/dummy-20.jpg', 1024, NOW(), NOW()),
    ('dummy-21.jpg','dummy-21.jpg','/images/dummy-21.jpg', 1024, NOW(), NOW()),
    ('dummy-22.jpg','dummy-22.jpg','/images/dummy-22.jpg', 1024, NOW(), NOW()),
    ('dummy-14.jpg','dummy-14.jpg','/images/dummy-14.jpg', 1024, NOW(), NOW());


BEGIN;

-- 1) 파일명 ↔ post_id 매핑해서 섹션 대표이미지로 연결
WITH map(file_name, post_id) AS (
    VALUES
        ('dummy-19.jpg', 19),
        ('dummy-20.jpg', 20),
        ('dummy-21.jpg', 21),
        ('dummy-22.jpg', 22),
        ('dummy-14.jpg', 14)
),
     f AS (
         SELECT id AS file_id, file_name
         FROM tbl_file
         WHERE file_name IN ('dummy-19.jpg','dummy-20.jpg','dummy-21.jpg','dummy-22.jpg','dummy-14.jpg')
     ),
     s AS (
         SELECT id AS section_id, post_id
         FROM tbl_post_section
         WHERE post_id IN (19,20,21,22,14)
     )
INSERT INTO tbl_post_section_file (file_id, post_section_id, image_type)
SELECT f.file_id, s.section_id, 'main'
FROM map
         JOIN f ON f.file_name = map.file_name
         JOIN s ON s.post_id   = map.post_id
-- 이미 매핑이 있다면 중복 방지 (옵션)
ON CONFLICT (file_id) DO NOTHING;

-- 2) 다이어리 메타 생성 (공개 + 경로 매핑)
--    스샷에 있던 걸 기준으로 예시 매핑: 19→18, 20→19, 21→20, 22→1
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES
    (19, 'public', 0, 0, 18),
    (20, 'public', 0, 0, 19),
    (21, 'public', 0, 0, 20),
    (22, 'public', 0, 0, 1)
ON CONFLICT (post_id) DO NOTHING;

COMMIT;


INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (19, 'public', 0, 0, 18);

-- post_id 19번에 diary 연결
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (19, 'public', 0, 0, 18);

-- post_id 20번에 diary 연결
INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES (20, 'public', 0, 0, 19);

SELECT * FROM tbl_diary WHERE post_id = 19;

UPDATE tbl_diary
SET diary_secret = 'public',
    diary_like_count = 0,
    diary_reply_count = 0,
    diary_country_path_id = 18
WHERE post_id = 19;

INSERT INTO tbl_diary (post_id, diary_secret, diary_like_count, diary_reply_count, diary_country_path_id)
VALUES
    (19, 'public', 12, 3, 18),
    (20, 'public', 8, 1, 19),
    (21, 'public', 23, 5, 20),
    (22, 'public', 5, 0, 1)
ON CONFLICT (post_id) DO UPDATE
    SET diary_secret = EXCLUDED.diary_secret,
        diary_like_count = EXCLUDED.diary_like_count,
        diary_reply_count = EXCLUDED.diary_reply_count,
        diary_country_path_id = EXCLUDED.diary_country_path_id;

INSERT INTO tbl_post_section (post_id, post_content)
VALUES
    (19, '더미 본문 19'),
    (20, '더미 본문 20'),
    (21, '더미 본문 21'),
    (22, '더미 본문 22');

INSERT INTO tbl_file (file_name, file_origin_name, file_path, file_size, created_datetime, updated_datetime)
VALUES
    ('dummy-19.jpg','dummy-19.jpg','/images/dummy-19.jpg', 1024, now(), now()),
    ('dummy-20.jpg','dummy-20.jpg','/images/dummy-20.jpg', 1024, now(), now()),
    ('dummy-21.jpg','dummy-21.jpg','/images/dummy-21.jpg', 1024, now(), now()),
    ('dummy-22.jpg','dummy-22.jpg','/images/dummy-22.jpg', 1024, now(), now());

SELECT id, file_name FROM tbl_file
WHERE file_name IN ('dummy-19.jpg','dummy-20.jpg','dummy-21.jpg','dummy-22.jpg');

SELECT id, post_id, post_content FROM tbl_post_section
WHERE post_id IN (19,20,21,22);

UPDATE tbl_post  SET post_status='active' WHERE id IN (19,20,21,22);
UPDATE tbl_diary SET diary_secret='public' WHERE post_id IN (19,20,21,22);

-- 파일 더미 데이터 (id는 identity면 자동 증가라면 빼고 넣어야 함)
INSERT INTO tbl_file (file_path, file_name, file_origin_name,file_size)
VALUES
    ('2025/10/01/banner4.png', 'banner4.png', '배너4.png',1000),
    ('2025/10/01/banner5.png', 'banner5.png', '배너5.png',1000);

INSERT INTO tbl_banner_file (file_id, banner_id)
VALUES
    (46, 1),
    (47, 2);


-- 좋아요 알람 더미
insert into tbl_like_alarm (alarm_status, like_id)
values ('unread', 1);

-- 다이어리 알람 더미
insert into tbl_diary_alarm (alarm_status, diary_id)
values ('unread', 1);

-- 멤버 알람 더미
insert into tbl_member_alarm (alarm_status, member_id)
values ('unread', 1);

-- 알림을 “받을” 유저 (A)
INSERT INTO tbl_member (member_name, member_phone, member_email, member_gender, member_role)
VALUES ('정이랑', '01088888888', 'a@gmail.com', 'female', 'member')
RETURNING id;

-- 결과 예시: A_ID = 1 (아래에서 이 값 사용)
-- 알림을 “발생시키는” 유저 (B)
INSERT INTO tbl_member (member_name, member_phone, member_email, member_gender, member_role)
VALUES ('손수영', '01077777777', 'b@gmail.com', 'female', 'member')
RETURNING id;

-- 결과 예시: B_ID = 2


INSERT INTO tbl_post (post_title, member_id, post_status)
VALUES ('알림 테스트 글', (SELECT id FROM tbl_member WHERE member_email='a@gmail.com'), 'active'::status)
RETURNING id;  -- POST_ID 메모 (예: 10)



INSERT INTO tbl_diary_country_path (
    country_start_date,
    country_end_date,
    member_id,
    country_id
)
VALUES (
           '2025-11-01',                -- 여행 시작일
           '2025-11-05',                -- 여행 종료일
           (SELECT id FROM tbl_member WHERE member_email = 'a@gmail.com'),  -- 정이랑 id
           (SELECT id FROM tbl_country LIMIT 1)   -- 존재하는 나라 중 하나 사용 (예: 1)
       )
RETURNING id;

INSERT INTO tbl_diary (
    post_id,
    diary_secret,
    diary_like_count,
    diary_reply_count,
    diary_country_path_id
)
VALUES (
           (SELECT id FROM tbl_post WHERE post_title = '알림 테스트 글'),
           'public'::secret,
           0,
           0,
           3  -- 위 RETURNING으로 나온 id 넣기
       );

SELECT post_id, diary_country_path_id, diary_secret
FROM tbl_diary
ORDER BY post_id DESC;

insert into tbl_member (member_name, member_email, member_password, member_role)
values ('test', 'test4@naver.com', 'tet1234', 'member');

select * from tbl_member;

insert into tbl_file (id, file_origin_name, file_name, file_path)
values (1, 'test.jpg', 'test.jpg', '/images/banner');



insert into tbl_file (file_origin_name, file_name, file_path, file_size)
values ('test.jpg', 'test.jpg', '/images/banner', 12345);


insert into tbl_file (file_origin_name, file_name, file_path, file_size)
values ('dummy.jpg', 'dummy.jpg', '/images/banner', 1024);
select * from tbl_file order by id desc limit 1;
delete from tbl_banner_file where file_id = 2;
insert into tbl_file (file_origin_name, file_name, file_path, file_size)
values ('newBanner.jpg', 'newBanner.jpg', '/images/banner', 2048);
insert into tbl_file (file_origin_name, file_name, file_path, file_size)
values ('updateBanner.jpg', 'updateBanner.jpg', '/images/banner', 1234);

select * from tbl_file;

select * from tbl_banner_file order by banner_id;
delete from tbl_banner_file where banner_id = 1 and file_id = 52;

select * from tbl_member;




-- 1) 신고 생성 → 새 id 받기
WITH new_report AS (
    INSERT INTO tbl_report (report_content, member_id)
        VALUES ('욕설이 심해요(더미)', 22)
        RETURNING id
)
-- 2) 신고-게시글 매핑 (IDENTITY 우회)
INSERT INTO tbl_post_report (report_id, post_id)
    OVERRIDING SYSTEM VALUE
SELECT id, 42 FROM new_report;

-- 3) 보기 좋은 시간(선택)
UPDATE tbl_report
SET created_datetime = NOW() - INTERVAL '12 minutes'
WHERE id = (SELECT max(id) FROM tbl_report WHERE member_id = 22);


WITH new_report AS (
    INSERT INTO tbl_report (report_content, member_id)
        VALUES ('스팸/광고 같아요(더미)', 22)
        RETURNING id
)
INSERT INTO tbl_post_report (report_id, post_id)
    OVERRIDING SYSTEM VALUE
SELECT id, 14 FROM new_report;

UPDATE tbl_report
SET created_datetime = NOW() - INTERVAL '6 minutes'
WHERE id = (SELECT max(id) FROM tbl_report WHERE member_id = 22);


-- 다이어리 목록 쪽
SELECT r.id AS report_id, r.created_datetime, r.report_content, r.report_process_status,
       p.post_title, p.id AS post_id
FROM view_report_post_report r
         JOIN view_post_diary p ON p.id = r.post_id
ORDER BY r.created_datetime DESC
LIMIT 10;

-- 기프트 목록 쪽
SELECT r.id AS report_id, r.created_datetime, r.report_content, r.report_process_status,
       p.post_title, p.id AS post_id
FROM view_report_post_report r
         JOIN view_post_purchase p ON p.id = r.post_id
ORDER BY r.created_datetime DESC
LIMIT 10;

insert into tbl_payment(created_datetime, updated_datetime, payment_status_id)
values (now(), now(), '8');

insert into tbl_payment_status(payment_phase, purchase_id, created_datetime, updated_datetime, member_id)
values ('success', 8,now(),now(),1);

select * from tbl_purchase;
select * from tbl_post;
select * from tbl_payment;
select * from tbl_member;
select *from tbl_payment_status;


-- ps.id 기준으로 결제 행이 2개 이상인 status 찾기
SELECT payment_status_id, COUNT(*)
FROM tbl_payment
GROUP BY payment_status_id
HAVING COUNT(*) > 1;

-- 문제 되는 id 하나 골라 상세 보기
SELECT *
FROM tbl_payment
WHERE payment_status_id = 8
ORDER BY updated_datetime DESC;

insert into tbl_file(file_origin_name, file_path, file_name, file_size)
values ('banner1.jpg','2025/10/15/wsadasadasadasdb.jpeg','wsadasadasadasdb.jpeg',1000),
       ('banner2.jpg','2025/10/15/snansasndadn_asd.jpeg','snansasndadn_asd.jpeg',1000),
       ('banner3.jpg','2025/10/15/wsadasadaasdm.jpeg','wsadasadaasdm.jpeg',1000),
       ('banner4.jpg','2025/10/15/wsadasadasadassnsasdb.jpeg','wsadasadasadassnsasdb.jpeg',1000),
       ('banner5.jpg','2025/10/15/wsadasadas12392asdb.jpeg','wsadasadas12392asdb.jpeg',1000);

insert into tbl_banner(banner_order)
values (1),(2),(3),(4),(5);

insert into tbl_banner_file(file_id, banner_id)
values (98,1),(99,2),(100,3),(101,4),(102,5);


select * from tbl_banner_file;

select * from tbl_file;

BEGIN;

-- 1) 멤버 더미 (관리자 1명 + 일반 회원 3명)
--   ※ tbl_member 컬럼이 더 있다면 NOT NULL 컬럼에 기본값을 채워줘야 함.
--   ※ id가 identity여도 명시 삽입하려면 OVERRIDING SYSTEM VALUE 사용.
INSERT INTO tbl_member (id, member_name) OVERRIDING SYSTEM VALUE
VALUES
    (900, '관리자'),
    (101, '김태민'),
    (102, '이가영'),
    (103, '홍길동')
ON CONFLICT (id) DO NOTHING;
-- 2) 문의 더미 (답변 완료/미답변이 섞이도록 6건)
INSERT INTO tbl_inquiry (id, inquiry_title, inquiry_content, member_id, created_datetime, updated_datetime)
    OVERRIDING SYSTEM VALUE
VALUES
    (201, '결제 관련 문의', '영수증을 다시 받을 수 있나요?', 101, NOW() - INTERVAL '7 days', NOW() - INTERVAL '7 days'),
    (202, '크루 가입 신청', '크루 승인까지 시간이 얼마나 걸리나요?', 102, NOW() - INTERVAL '6 days', NOW() - INTERVAL '6 days'),
    (203, '게시글 신고', '부적절한 게시글이 있어요', 103, NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days'),
    (204, '계정 비밀번호', '비밀번호 재설정 메일이 오지 않아요', 101, NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days'),
    (205, '프로필 이미지', '이미지가 깨져 보여요', 102, NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days'),
    (206, '크루 채팅', '채팅 알림이 오락가락해요', 103, NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days')
ON CONFLICT (id) DO NOTHING;

-- 3) 답변 더미 (일부 문의에는 답변 달고, 일부는 미답변으로 남김)
--    201, 203, 206 은 답변 ‘있음’ / 202, 204, 205 는 ‘없음’ 상태가 되도록
INSERT INTO tbl_inquiry_reply (id, inquiry_reply_content, member_id, inquiry_id, created_datetime, updated_datetime)
    OVERRIDING SYSTEM VALUE
VALUES
    (301, '영수증은 마이페이지 > 결제내역에서 재발급 가능합니다.', 900, 201, NOW() - INTERVAL '6 days', NOW() - INTERVAL '6 days'),
    (302, '부적절한 게시글은 신고 접수되어 확인 중입니다. 조치 예정입니다.', 900, 203, NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days'),
    (303, '채팅 알림 개선 패치를 반영했습니다. 앱 재실행 후 확인 부탁드립니다.', 900, 206, NOW() - INTERVAL '1 days', NOW() - INTERVAL '1 days')
ON CONFLICT (id) DO NOTHING;


select * from tbl_banner;
select * from tbl_banner_file;
select * from tbl_file;

delete from tbl_banner;

select * from view_file_banner_file;

insert into tbl_banner(banner_order)
values (2);

insert into tbl_banner_file(file_id, banner_id)
values (34, 11);

select * from tbl_member;
select * from tbl_post_report;
select * from tbl_post;
select * from tbl_report;
select * from tbl_accompany_path;
select * from tbl_accompany;
select * from tbl_country;
select * from tbl_diary_country;

-- 동행 신고

insert into tbl_post(post_title, post_read_count, post_status, member_id)
values ('숏크루 신고 테스트3', '70', 'active','33' );

insert into tbl_report(report_content, report_process_status, member_id)
values ('숏크루 신고3', 'pending', '33');

insert into tbl_post_report(report_id,post_id)
values (20,52);



insert into tbl_country(country_name)
values ('유럽');

insert into tbl_accompany(post_id, accompany_status, accompany_age_range)
values ('50','short','20');


insert into tbl_accompany_path (country_start_date, country_end_date, accompany_id, country_id)
values ('2014-10-8', '2025-10-10', '35', '26');



