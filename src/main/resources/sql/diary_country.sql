create table tbl_diary_country
(
    id         bigint generated always as identity primary key,
    post_id    bigint,
    country_id bigint not null,
    constraint fk_diary_country_country foreign key (country_id)
        references tbl_country (id),
    constraint fk_diary_country_tbl_diary foreign key (post_id)
        references tbl_diary (post_id)
);
