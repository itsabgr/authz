create table if not exists authz (
                                     "user" text not null,
                                     "relation" text not null,
                                     "entity" text not null,
                                     primary key ("user","relation","entity")
    );


create or replace function "authz_check"(
    "u" text,
    "r" text ,
    "e" text
) returns int
    language plpgsql
as $$
declare n int = 0;
begin

    if u = '' and r = '' and e = '' then
        raise 'empty arguments';
end if;

select count(*) into n from authz where
    ("user" = u and "relation" = r and "entity" = e) or
    ("user" = u and "relation" = '' and "entity" = '') or
    ("user" = '' and "relation" = r and "entity" = '') or
    ("user" = '' and "relation" = '' and "entity" = e) or
    ("user" = '' and "relation" = r and "entity" = e) or
    ("user" = u and "relation" = '' and "entity" = e) or
    ("user" = u and "relation" = r and "entity" = '') limit 1;

return n;

end;$$;


create or replace function "authz_permit_trigger"() returns trigger language plpgsql as $$ begin
    if authz_check(new."user",new."relation",new."entity") > 0 then
        raise 'permission already exists';
end if;
return new;

end;$$;


create or replace function "authz_no_update"() returns trigger language plpgsql as $$ begin raise 'updates are not allowed'; end;$$;



create trigger authz_permit_check before insert on authz for each row execute function authz_permit_trigger();


create trigger authz_prevent_update before update on authz for each row execute function authz_no_update();

