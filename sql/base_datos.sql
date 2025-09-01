--
-- PostgreSQL database dump
--

-- Dumped from database version 16.9 (Ubuntu 16.9-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.9 (Ubuntu 16.9-0ubuntu0.24.04.1)

-- Started on 2025-08-31 20:06:49 -04

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- TOC entry 8 (class 2615 OID 26249)
-- Name: usuarios_dat; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA usuarios_dat;


ALTER SCHEMA usuarios_dat OWNER TO postgres;

--
-- TOC entry 3738 (class 0 OID 0)
-- Dependencies: 8
-- Name: SCHEMA usuarios_dat; Type: COMMENT; Schema: -; Owner: postgres
--

COMMENT ON SCHEMA usuarios_dat IS 'esquema donde se almacenaran los datos de los usuarios';


--
-- TOC entry 10 (class 2615 OID 26251)
-- Name: usuarios_domi; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA usuarios_domi;


ALTER SCHEMA usuarios_domi OWNER TO postgres;

--
-- TOC entry 3739 (class 0 OID 0)
-- Dependencies: 10
-- Name: SCHEMA usuarios_domi; Type: COMMENT; Schema: -; Owner: postgres
--

COMMENT ON SCHEMA usuarios_domi IS 'esquema para almcenar los domicilios de los usuarios';


--
-- TOC entry 9 (class 2615 OID 26250)
-- Name: usuarios_seg; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA usuarios_seg;


ALTER SCHEMA usuarios_seg OWNER TO postgres;

--
-- TOC entry 3740 (class 0 OID 0)
-- Dependencies: 9
-- Name: SCHEMA usuarios_seg; Type: COMMENT; Schema: -; Owner: postgres
--

COMMENT ON SCHEMA usuarios_seg IS 'esquema para amacenar la logica de la seguridad de los usuarios';


--
-- TOC entry 2 (class 3079 OID 26353)
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA pg_catalog;


--
-- TOC entry 3741 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- TOC entry 3 (class 3079 OID 26473)
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- TOC entry 3742 (class 0 OID 0)
-- Dependencies: 3
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- TOC entry 308 (class 1255 OID 26513)
-- Name: actualizar_clave(bigint, text); Type: PROCEDURE; Schema: usuarios_dat; Owner: postgres
--

CREATE PROCEDURE usuarios_dat.actualizar_clave(IN p_usu_id bigint, IN p_cla text)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_cla_actual TEXT;
BEGIN
    -- 1. Obtener la clave actual del usuario
    SELECT usu_cla INTO v_cla_actual
    FROM usuarios_dat.usuarios
    WHERE usu_id = p_usu_id;

    -- 2. Validar existencia del usuario
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Usuario con ID % no existe', p_usu_id USING ERRCODE = 'P0002';
    END IF;

    -- 3. Verificar que la nueva clave no sea igual a la actual
    IF crypt(p_cla, v_cla_actual) = v_cla_actual THEN
        RAISE EXCEPTION 'La clave ingresada ya está en uso' USING ERRCODE = 'P0001';
    END IF;

    -- 4. Actualizar la clave con nuevo salt
    UPDATE usuarios_dat.usuarios
    SET usu_cla = crypt(p_cla, gen_salt('bf'))
    WHERE usu_id = p_usu_id;

    -- 5. Mensaje de confirmación
    RAISE NOTICE 'Clave actualizada exitosamente';
END;
$$;


ALTER PROCEDURE usuarios_dat.actualizar_clave(IN p_usu_id bigint, IN p_cla text) OWNER TO postgres;

--
-- TOC entry 279 (class 1255 OID 26514)
-- Name: actualizar_usuario(bigint, character varying, character varying, date); Type: PROCEDURE; Schema: usuarios_dat; Owner: postgres
--

CREATE PROCEDURE usuarios_dat.actualizar_usuario(IN p_usu_id bigint, IN p_nom character varying, IN p_apell character varying, IN p_fn date)
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- 1. Normalizar entradas
    p_nom := LOWER(TRIM(p_nom));
    p_apell := LOWER(TRIM(p_apell));

    -- 2. Validar existencia del usuario
    IF NOT EXISTS (
        SELECT 1 FROM usuarios_dat.usuarios WHERE usu_id = p_usu_id
    ) THEN
        RAISE EXCEPTION 'Usuario con ID % no existe', p_usu_id USING ERRCODE = 'P0002';
    END IF;

    -- 3. Actualizar datos
    UPDATE usuarios_dat.usuarios
    SET usu_nom = p_nom,
        usu_apell = p_apell,
        usu_fn = p_fn
    WHERE usu_id = p_usu_id;

    -- 4. (Opcional) Mensaje de confirmación
    RAISE NOTICE 'Datos actualizados correctamente';
END;
$$;


ALTER PROCEDURE usuarios_dat.actualizar_usuario(IN p_usu_id bigint, IN p_nom character varying, IN p_apell character varying, IN p_fn date) OWNER TO postgres;

--
-- TOC entry 262 (class 1255 OID 26518)
-- Name: eliminar_usuario(bigint); Type: PROCEDURE; Schema: usuarios_dat; Owner: postgres
--

CREATE PROCEDURE usuarios_dat.eliminar_usuario(IN p_usu_id bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- 1. Verificar que el usuario exista
    IF NOT EXISTS (
        SELECT 1 FROM usuarios_dat.usuarios WHERE usu_id = p_usu_id
    ) THEN
        RAISE EXCEPTION 'Usuario ingresado no existe' USING ERRCODE = 'P0002';
    END IF;

    -- 2. Eliminar el usuario
    DELETE FROM usuarios_dat.usuarios
    WHERE usu_id = p_usu_id;

    -- 3. Confirmación
    RAISE NOTICE 'El usuario fue eliminado exitosamente';
END;
$$;


ALTER PROCEDURE usuarios_dat.eliminar_usuario(IN p_usu_id bigint) OWNER TO postgres;

--
-- TOC entry 289 (class 1255 OID 26548)
-- Name: inicio_sesion(character varying, text); Type: FUNCTION; Schema: usuarios_dat; Owner: postgres
--

CREATE FUNCTION usuarios_dat.inicio_sesion(p_usu_corr character varying, p_usu_cla text) RETURNS TABLE(r_usu_id bigint, r_usu_rol character varying)
    LANGUAGE plpgsql
    AS $$
DECLARE
	v_usu_id BIGINT;
	v_usu_rol VARCHAR;
BEGIN
	-- 1. Verificar existencia del correo
	IF NOT EXISTS (SELECT 1 FROM usuarios_dat.usuarios WHERE usu_corr = p_usu_corr) THEN
		RAISE EXCEPTION 'El correo: % no se encuentra registrado', p_usu_corr USING ERRCODE = 'P0002';
	END IF;

	SELECT usu_id INTO v_usu_id FROM usuarios_dat.usuarios
	WHERE usu_corr = p_usu_corr AND crypt(p_usu_cla, usu_cla) = usu_cla;

	IF NOT FOUND THEN
		RAISE EXCEPTION 'Credenciales Invalidas. Verifique he intente nuevamente' USING ERRCODE = 'P0001';
	END IF;

	SELECT rol.rol INTO v_usu_rol FROM usuarios_seg.seg_usu as seg
	JOIN usuarios_seg.roles_usu as rol
		ON rol.rol_id = seg.seg_rol
	WHERE seg_usu = v_usu_id;

	RETURN QUERY SELECT v_usu_id, v_usu_rol;
END;
$$;


ALTER FUNCTION usuarios_dat.inicio_sesion(p_usu_corr character varying, p_usu_cla text) OWNER TO postgres;

--
-- TOC entry 263 (class 1255 OID 26515)
-- Name: obtener_datos(bigint); Type: FUNCTION; Schema: usuarios_dat; Owner: postgres
--

CREATE FUNCTION usuarios_dat.obtener_datos(p_usu_id bigint) RETURNS TABLE(r_usu_nom character varying, r_usu_apell character varying, r_usu_fn date, r_usu_corr character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
	RETURN QUERY
	SELECT usu_nom, usu_apell, usu_fn, usu_corr
	FROM usuarios_dat.usuarios
	WHERE usu_id = p_usu_id;

	IF NOT FOUND THEN
		RAISE EXCEPTION 'Ha ocurrido un error al tratar de obtener los datos del usuario' USING ERRCODE = 'P0001';
	END IF;
END;
$$;


ALTER FUNCTION usuarios_dat.obtener_datos(p_usu_id bigint) OWNER TO postgres;

--
-- TOC entry 283 (class 1255 OID 26702)
-- Name: obtener_datos_actualizables(integer); Type: FUNCTION; Schema: usuarios_dat; Owner: postgres
--

CREATE FUNCTION usuarios_dat.obtener_datos_actualizables(user_id integer) RETURNS TABLE(r_name character varying, r_lastname character varying, r_fn date)
    LANGUAGE plpgsql
    AS $$
BEGIN
	RETURN QUERY
	SELECT usu_nom, usu_apell, usu_fn
	FROM usuarios_dat.usuarios
	WHERE usu_id = user_id;

	IF NOT FOUND THEN
		RAISE EXCEPTION 'No se han encontrado resultados para el ID (%)', user_id USING ERRCODE = 'P0001';
	END IF;
END;
$$;


ALTER FUNCTION usuarios_dat.obtener_datos_actualizables(user_id integer) OWNER TO postgres;

--
-- TOC entry 281 (class 1255 OID 26701)
-- Name: obtener_nombre(integer); Type: FUNCTION; Schema: usuarios_dat; Owner: postgres
--

CREATE FUNCTION usuarios_dat.obtener_nombre(user_id integer) RETURNS character varying
    LANGUAGE plpgsql
    AS $$
declare
	v_usu_nom varchar;
begin
	select usu_nom into v_usu_nom from usuarios_dat.usuarios where usu_id = user_id;

	if not found then
		raise exception 'Error al buscar el usuario con el ID: %', user_id using errcode = 'P0001';
	end if;

	return v_usu_nom;
end;
$$;


ALTER FUNCTION usuarios_dat.obtener_nombre(user_id integer) OWNER TO postgres;

--
-- TOC entry 278 (class 1255 OID 26519)
-- Name: registrar_rol(character varying, character varying); Type: PROCEDURE; Schema: usuarios_dat; Owner: postgres
--

CREATE PROCEDURE usuarios_dat.registrar_rol(IN p_rol character varying, IN p_des character varying)
    LANGUAGE plpgsql
    AS $$
 BEGIN
    p_rol := LOWER(TRIM(p_rol));
    p_des := LOWER(TRIM(p_des));

    -- 1. verificar la existencia del rol
    IF EXISTS (SELECT 1 FROM usuarios_seg.roles_usu WHERE rol = p_rol) THEN
        RAISE EXCEPTION 'El rol: % ya se encuentra registrado', p_rol USING ERRCODE = 'P0001';
    END IF;

    -- 2. Insertar nuevo rol
    INSERT INTO usuarios_seg.roles_usu (rol, rol_des) VALUES (p_rol, p_des);

    -- 3. Devolver respuesta
    RAISE NOTICE 'El rol % ha sido registrado exitosamente', p_rol;
 END;
 $$;


ALTER PROCEDURE usuarios_dat.registrar_rol(IN p_rol character varying, IN p_des character varying) OWNER TO postgres;

--
-- TOC entry 307 (class 1255 OID 26696)
-- Name: registrar_usuario(character varying, character varying, date, character varying, text, character varying); Type: FUNCTION; Schema: usuarios_dat; Owner: postgres
--

CREATE FUNCTION usuarios_dat.registrar_usuario(p_nom character varying, p_apell character varying, p_fn date, p_corr character varying, p_cla text, p_rol character varying DEFAULT 'client'::character varying) RETURNS TABLE(r_usu_id bigint, r_usu_rol character varying)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_usu_id BIGINT;
    v_rol_id BIGINT;
    v_seg_ini  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
    v_seg_act  CHAR DEFAULT 'A';           -- usuario activo?
BEGIN
    -- Normalizar entradas
    p_nom      := LOWER(TRIM(p_nom));
    p_apell    := LOWER(TRIM(p_apell));
    p_corr     := LOWER(TRIM(p_corr));
    p_rol      := LOWER(TRIM(p_rol));

    -- Verificar que el rol exista
    SELECT rol_id INTO v_rol_id
    FROM usuarios_seg.roles_usu
    WHERE rol = p_rol
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'El rol ingresado (%) es incorrecto. Verifique e intente nuevamente', p_rol
            USING ERRCODE = 'P0003';
    END IF;

    -- Insertar usuario y capturar ID generado
    INSERT INTO usuarios_dat.usuarios (
        usu_nom,
        usu_apell,
        usu_fn,
        usu_corr,
        usu_cla
    ) VALUES (
        p_nom,
        p_apell,
        p_fn,
        p_corr,
        crypt(p_cla, gen_salt('bf'))
    )
    RETURNING usu_id INTO v_usu_id;

    -- Crear datos de seguridad
    INSERT INTO usuarios_seg.seg_usu (seg_act, seg_ini, seg_rol, seg_usu)
    VALUES (v_seg_act, v_seg_ini, v_rol_id, v_usu_id);

    -- Devolver el ID creado
    RETURN QUERY SELECT v_usu_id, p_rol;

EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'El correo: % ya se encuentra en uso', p_corr
            USING ERRCODE = '23505';
END;
$$;


ALTER FUNCTION usuarios_dat.registrar_usuario(p_nom character varying, p_apell character varying, p_fn date, p_corr character varying, p_cla text, p_rol character varying) OWNER TO postgres;

--
-- TOC entry 270 (class 1255 OID 26544)
-- Name: eliminar_estado(integer); Type: PROCEDURE; Schema: usuarios_domi; Owner: postgres
--

CREATE PROCEDURE usuarios_domi.eliminar_estado(IN p_id_estado integer)
    LANGUAGE plpgsql
    AS $$
DECLARE
    -- Se declara una variable para el ID del municipio
    v_muni_id INTEGER;
BEGIN
    -- Verificar existencia
    IF NOT EXISTS (SELECT 1 FROM usuarios_domi.estados WHERE est_id = p_id_estado) THEN
        RAISE EXCEPTION 'El Estado con ID %, no existe', p_id_estado
            USING ERRCODE = 'P0001';
    END IF;

    -- Eliminar municipios (y sus parroquias/domicilios)
    -- Se usa una variable escalar para capturar el ID del municipio en cada iteración.
    FOR v_muni_id IN SELECT mun_id FROM usuarios_domi.muni WHERE mun_est = p_id_estado LOOP
        CALL usuarios_domi.eliminar_estado(v_muni_id);
    END LOOP;

    -- Eliminar estado
    DELETE FROM usuarios_domi.estados
    WHERE est_id = p_id_estado;

    RAISE NOTICE 'El Estado con ID %, fue eliminado exitosamente', p_id_estado;
END;
$$;


ALTER PROCEDURE usuarios_domi.eliminar_estado(IN p_id_estado integer) OWNER TO postgres;

--
-- TOC entry 287 (class 1255 OID 26543)
-- Name: eliminar_municipio(integer); Type: PROCEDURE; Schema: usuarios_domi; Owner: postgres
--

CREATE PROCEDURE usuarios_domi.eliminar_municipio(IN p_id_muni integer)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_parr_id INTEGER; -- Se declara una variable para el ID de la parroquia
BEGIN
    -- Verificar existencia
    IF NOT EXISTS (SELECT 1 FROM usuarios_domi.muni WHERE mun_id = p_id_muni) THEN
        RAISE EXCEPTION 'El Municipio con ID %, no existe', p_id_muni
            USING ERRCODE = 'P0001';
    END IF;

    -- Eliminar parroquias (y sus domicilios)
    -- Se usa una variable escalar para capturar el ID de la parroquia en cada iteración.
    FOR v_parr_id IN SELECT parr_id FROM usuarios_domi.parro WHERE parr_mun = p_id_muni LOOP
        CALL usuarios_domi.borrar_parroquia(v_parr_id);
    END LOOP;

    -- Eliminar municipio
    DELETE FROM usuarios_domi.muni
    WHERE mun_id = p_id_muni;

    RAISE NOTICE 'El Municipio con ID %, fue eliminado exitosamente', p_id_muni;
END;
$$;


ALTER PROCEDURE usuarios_domi.eliminar_municipio(IN p_id_muni integer) OWNER TO postgres;

--
-- TOC entry 286 (class 1255 OID 26542)
-- Name: eliminar_parroquia(integer); Type: PROCEDURE; Schema: usuarios_domi; Owner: postgres
--

CREATE PROCEDURE usuarios_domi.eliminar_parroquia(IN p_id_parro integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Verificar existencia
    IF NOT EXISTS (SELECT 1 FROM usuarios_domi.parro WHERE parr_id = p_id_parro) THEN
        RAISE EXCEPTION 'La Parroquia con ID %, no existe', p_id_parro
            USING ERRCODE = 'P0001';
    END IF;

    -- Eliminar domicilios asociados
    DELETE FROM usuarios_domi.dom_usu
    WHERE dom_parr = p_id_parro;

    -- Eliminar parroquia
    DELETE FROM usuarios_domi.parro
    WHERE parr_id = p_id_parro;

    RAISE NOTICE 'La Parroquia con ID %, fue eliminada exitosamente', p_id_parro;
END;
$$;


ALTER PROCEDURE usuarios_domi.eliminar_parroquia(IN p_id_parro integer) OWNER TO postgres;

--
-- TOC entry 320 (class 1255 OID 26529)
-- Name: registrar_estado(character varying); Type: PROCEDURE; Schema: usuarios_domi; Owner: postgres
--

CREATE PROCEDURE usuarios_domi.registrar_estado(IN p_est character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
	p_est := LOWER(TRIM(p_est));

	-- verificar existencia de estado
	IF EXISTS (SELECT 1 FROM usuarios_domi.estados WHERE estado = p_est) THEN
		RAISE EXCEPTION 'El Estado %, ya se encuentra registrado.', p_est USING ERRCODE = 'P0001';
	END IF;

	-- insertar nuevo estado
	INSERT INTO usuarios_domi.estados (estado) VALUES (p_est);

	-- devolver resultado
	RAISE NOTICE 'El Estado %, ha sido registrado exitosamente.', p_est;
END;
$$;


ALTER PROCEDURE usuarios_domi.registrar_estado(IN p_est character varying) OWNER TO postgres;

--
-- TOC entry 295 (class 1255 OID 26532)
-- Name: registrar_municipio(character varying, bigint); Type: PROCEDURE; Schema: usuarios_domi; Owner: postgres
--

CREATE PROCEDURE usuarios_domi.registrar_municipio(IN p_muni character varying, IN p_id_est bigint)
    LANGUAGE plpgsql
    AS $$
BEGIN
	p_muni := LOWER(TRIM(p_muni));
	BEGIN
		-- verificar existencia del municipio
		IF EXISTS (SELECT 1 FROM usuarios_domi.muni WHERE mun = p_muni AND mun_est = p_id_est) THEN
			RAISE EXCEPTION 'El municipio %, ya se encuentra registrado', p_muni USING ERRCODE = 'P0001';
		END IF;
	
		-- verificar existencia del ID del estado
		IF NOT EXISTS (SELECT 1 FROM usuarios_domi.estados WHERE est_id = p_id_est) THEN
			RAISE EXCEPTION 'El Estado ingresado (%) no ha sido encontrado', p_id_est USING ERRCODE = 'P0002';
		END IF;
	
		-- registrar municipio
		INSERT INTO usuarios_domi.muni (mun, mun_est) VALUES (p_muni, p_id_est);
	
		-- devolver mensaje (exito)
		RAISE NOTICE 'El Municipio %, ha sido registrado exitosamente', p_muni;

	EXCEPTION
		WHEN OTHERS THEN
			RAISE;
	END;
END;
$$;


ALTER PROCEDURE usuarios_domi.registrar_municipio(IN p_muni character varying, IN p_id_est bigint) OWNER TO postgres;

--
-- TOC entry 280 (class 1255 OID 26533)
-- Name: registrar_parroquia(character varying, integer); Type: PROCEDURE; Schema: usuarios_domi; Owner: postgres
--

CREATE PROCEDURE usuarios_domi.registrar_parroquia(IN p_parro character varying, IN p_id_muni integer)
    LANGUAGE plpgsql
    AS $$
BEGIN
	p_parro := LOWER(TRIM(p_parro));

	BEGIN
		-- verificar existencia del municipio
		IF NOT EXISTS (SELECT 1 FROM usuarios_domi.muni WHERE mun_id = p_id_muni) THEN
			RAISE EXCEPTION 'El Municipio ingresado (%), no ha sido encontrado', p_id_muni USING ERRCODE = 'P0001';
		END IF;

		-- verificar existencia de la parroquia
		IF EXISTS (SELECT 1 FROM usuarios_domi.parro WHERE parro = p_parro AND parr_mun = p_id_muni) THEN
			RAISE EXCEPTION 'La Parroquia %, ya se encuentra registrada', p_parro USING ERRCODE = 'P0002';
		END IF;

		-- registrar parroquia
		INSERT INTO usuarios_domi.parro (parro, parr_mun) VALUES (p_parro, p_id_muni);

		-- devolver resultado (exito)
		RAISE NOTICE 'La Parroquia %, ha sido registrada exitosamente', p_parro;
	EXCEPTION
		WHEN OTHERS THEN
			RAISE;
	END;
END;
$$;


ALTER PROCEDURE usuarios_domi.registrar_parroquia(IN p_parro character varying, IN p_id_muni integer) OWNER TO postgres;

--
-- TOC entry 306 (class 1255 OID 26521)
-- Name: registrar_rol(character varying, character varying); Type: PROCEDURE; Schema: usuarios_seg; Owner: postgres
--

CREATE PROCEDURE usuarios_seg.registrar_rol(IN p_rol character varying, IN p_des character varying)
    LANGUAGE plpgsql
    AS $$
 BEGIN
    p_rol := LOWER(TRIM(p_rol));
    p_des := LOWER(TRIM(p_des));

    -- 1. verificar la existencia del rol
    IF EXISTS (SELECT 1 FROM usuarios_seg.roles_usu WHERE rol = p_rol) THEN
        RAISE EXCEPTION 'El rol: % ya se encuentra registrado', p_rol USING ERRCODE = 'P0001';
    END IF;

    -- 2. Insertar nuevo rol
    INSERT INTO usuarios_seg.roles_usu (rol, rol_des) VALUES (p_rol, p_des);

    -- 3. Devolver respuesta
    RAISE NOTICE 'El rol % ha sido registrado exitosamente', p_rol;
 END;
 $$;


ALTER PROCEDURE usuarios_seg.registrar_rol(IN p_rol character varying, IN p_des character varying) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 247 (class 1259 OID 26572)
-- Name: auth_group; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.auth_group (
    id integer NOT NULL,
    name character varying(150) NOT NULL
);


ALTER TABLE public.auth_group OWNER TO postgres;

--
-- TOC entry 246 (class 1259 OID 26571)
-- Name: auth_group_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.auth_group ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_group_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- TOC entry 249 (class 1259 OID 26580)
-- Name: auth_group_permissions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.auth_group_permissions (
    id bigint NOT NULL,
    group_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.auth_group_permissions OWNER TO postgres;

--
-- TOC entry 248 (class 1259 OID 26579)
-- Name: auth_group_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.auth_group_permissions ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_group_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- TOC entry 245 (class 1259 OID 26566)
-- Name: auth_permission; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.auth_permission (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    content_type_id integer NOT NULL,
    codename character varying(100) NOT NULL
);


ALTER TABLE public.auth_permission OWNER TO postgres;

--
-- TOC entry 244 (class 1259 OID 26565)
-- Name: auth_permission_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.auth_permission ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_permission_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- TOC entry 251 (class 1259 OID 26586)
-- Name: auth_user; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.auth_user (
    id integer NOT NULL,
    password character varying(128) NOT NULL,
    last_login timestamp with time zone,
    is_superuser boolean NOT NULL,
    username character varying(150) NOT NULL,
    first_name character varying(150) NOT NULL,
    last_name character varying(150) NOT NULL,
    email character varying(254) NOT NULL,
    is_staff boolean NOT NULL,
    is_active boolean NOT NULL,
    date_joined timestamp with time zone NOT NULL
);


ALTER TABLE public.auth_user OWNER TO postgres;

--
-- TOC entry 253 (class 1259 OID 26594)
-- Name: auth_user_groups; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.auth_user_groups (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    group_id integer NOT NULL
);


ALTER TABLE public.auth_user_groups OWNER TO postgres;

--
-- TOC entry 252 (class 1259 OID 26593)
-- Name: auth_user_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.auth_user_groups ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_user_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- TOC entry 250 (class 1259 OID 26585)
-- Name: auth_user_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.auth_user ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- TOC entry 255 (class 1259 OID 26600)
-- Name: auth_user_user_permissions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.auth_user_user_permissions (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.auth_user_user_permissions OWNER TO postgres;

--
-- TOC entry 254 (class 1259 OID 26599)
-- Name: auth_user_user_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.auth_user_user_permissions ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.auth_user_user_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- TOC entry 257 (class 1259 OID 26658)
-- Name: django_admin_log; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.django_admin_log (
    id integer NOT NULL,
    action_time timestamp with time zone NOT NULL,
    object_id text,
    object_repr character varying(200) NOT NULL,
    action_flag smallint NOT NULL,
    change_message text NOT NULL,
    content_type_id integer,
    user_id integer NOT NULL,
    CONSTRAINT django_admin_log_action_flag_check CHECK ((action_flag >= 0))
);


ALTER TABLE public.django_admin_log OWNER TO postgres;

--
-- TOC entry 256 (class 1259 OID 26657)
-- Name: django_admin_log_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.django_admin_log ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.django_admin_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- TOC entry 243 (class 1259 OID 26558)
-- Name: django_content_type; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.django_content_type (
    id integer NOT NULL,
    app_label character varying(100) NOT NULL,
    model character varying(100) NOT NULL
);


ALTER TABLE public.django_content_type OWNER TO postgres;

--
-- TOC entry 242 (class 1259 OID 26557)
-- Name: django_content_type_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.django_content_type ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.django_content_type_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- TOC entry 241 (class 1259 OID 26550)
-- Name: django_migrations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.django_migrations (
    id bigint NOT NULL,
    app character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    applied timestamp with time zone NOT NULL
);


ALTER TABLE public.django_migrations OWNER TO postgres;

--
-- TOC entry 240 (class 1259 OID 26549)
-- Name: django_migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.django_migrations ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.django_migrations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- TOC entry 258 (class 1259 OID 26686)
-- Name: django_session; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.django_session (
    session_key character varying(40) NOT NULL,
    session_data text NOT NULL,
    expire_date timestamp with time zone NOT NULL
);


ALTER TABLE public.django_session OWNER TO postgres;

--
-- TOC entry 221 (class 1259 OID 26253)
-- Name: usuarios; Type: TABLE; Schema: usuarios_dat; Owner: postgres
--

CREATE TABLE usuarios_dat.usuarios (
    usu_id bigint NOT NULL,
    usu_nom character varying(50) NOT NULL,
    usu_apell character varying(50) NOT NULL,
    usu_fn date NOT NULL,
    usu_corr character varying(100) NOT NULL,
    usu_cla text NOT NULL
);


ALTER TABLE usuarios_dat.usuarios OWNER TO postgres;

--
-- TOC entry 3743 (class 0 OID 0)
-- Dependencies: 221
-- Name: TABLE usuarios; Type: COMMENT; Schema: usuarios_dat; Owner: postgres
--

COMMENT ON TABLE usuarios_dat.usuarios IS 'tabla para el almacenamiento de los usuarios';


--
-- TOC entry 3744 (class 0 OID 0)
-- Dependencies: 221
-- Name: COLUMN usuarios.usu_id; Type: COMMENT; Schema: usuarios_dat; Owner: postgres
--

COMMENT ON COLUMN usuarios_dat.usuarios.usu_id IS 'ID del usuario';


--
-- TOC entry 3745 (class 0 OID 0)
-- Dependencies: 221
-- Name: COLUMN usuarios.usu_nom; Type: COMMENT; Schema: usuarios_dat; Owner: postgres
--

COMMENT ON COLUMN usuarios_dat.usuarios.usu_nom IS 'campo para los nombres del usuario, ej: ''Juan Antonio''';


--
-- TOC entry 3746 (class 0 OID 0)
-- Dependencies: 221
-- Name: COLUMN usuarios.usu_apell; Type: COMMENT; Schema: usuarios_dat; Owner: postgres
--

COMMENT ON COLUMN usuarios_dat.usuarios.usu_apell IS 'campo para almacenar los apellidos de los usuarios. ej: ''Contreras Sayago''';


--
-- TOC entry 3747 (class 0 OID 0)
-- Dependencies: 221
-- Name: COLUMN usuarios.usu_fn; Type: COMMENT; Schema: usuarios_dat; Owner: postgres
--

COMMENT ON COLUMN usuarios_dat.usuarios.usu_fn IS 'campo para almacenar la fecha de nacimiento del usuario, ej: ''17/05/1999''';


--
-- TOC entry 3748 (class 0 OID 0)
-- Dependencies: 221
-- Name: COLUMN usuarios.usu_corr; Type: COMMENT; Schema: usuarios_dat; Owner: postgres
--

COMMENT ON COLUMN usuarios_dat.usuarios.usu_corr IS 'campo para almacenar el correo electronico de los usuario, ej: ''admin@admin.com''';


--
-- TOC entry 3749 (class 0 OID 0)
-- Dependencies: 221
-- Name: COLUMN usuarios.usu_cla; Type: COMMENT; Schema: usuarios_dat; Owner: postgres
--

COMMENT ON COLUMN usuarios_dat.usuarios.usu_cla IS 'campo para almacenar la clave del usuario (hasheada)';


--
-- TOC entry 220 (class 1259 OID 26252)
-- Name: usuarios_usu_id_seq; Type: SEQUENCE; Schema: usuarios_dat; Owner: postgres
--

CREATE SEQUENCE usuarios_dat.usuarios_usu_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_dat.usuarios_usu_id_seq OWNER TO postgres;

--
-- TOC entry 3750 (class 0 OID 0)
-- Dependencies: 220
-- Name: usuarios_usu_id_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_dat; Owner: postgres
--

ALTER SEQUENCE usuarios_dat.usuarios_usu_id_seq OWNED BY usuarios_dat.usuarios.usu_id;


--
-- TOC entry 239 (class 1259 OID 26313)
-- Name: dom_usu; Type: TABLE; Schema: usuarios_domi; Owner: postgres
--

CREATE TABLE usuarios_domi.dom_usu (
    dom_id bigint NOT NULL,
    dom_com text NOT NULL,
    dom_parr bigint NOT NULL,
    dom_usu bigint NOT NULL
);


ALTER TABLE usuarios_domi.dom_usu OWNER TO postgres;

--
-- TOC entry 3751 (class 0 OID 0)
-- Dependencies: 239
-- Name: TABLE dom_usu; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON TABLE usuarios_domi.dom_usu IS 'tabla para almacenar los domicilios de los usuarios';


--
-- TOC entry 3752 (class 0 OID 0)
-- Dependencies: 239
-- Name: COLUMN dom_usu.dom_id; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.dom_usu.dom_id IS 'ID para cada domicilio';


--
-- TOC entry 3753 (class 0 OID 0)
-- Dependencies: 239
-- Name: COLUMN dom_usu.dom_com; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.dom_usu.dom_com IS 'campo para almcenar la direccion exacta del usuario, ej: ''Calle 12, carrera 5, Sector las vegas''';


--
-- TOC entry 3754 (class 0 OID 0)
-- Dependencies: 239
-- Name: COLUMN dom_usu.dom_parr; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.dom_usu.dom_parr IS 'campo para almacenar la parroquia a la que pertenece cada usuario';


--
-- TOC entry 3755 (class 0 OID 0)
-- Dependencies: 239
-- Name: COLUMN dom_usu.dom_usu; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.dom_usu.dom_usu IS 'campo para almacenar el ID de usuario correspondiente a cada domicilio';


--
-- TOC entry 236 (class 1259 OID 26310)
-- Name: dom_usu_dom_id_seq; Type: SEQUENCE; Schema: usuarios_domi; Owner: postgres
--

CREATE SEQUENCE usuarios_domi.dom_usu_dom_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_domi.dom_usu_dom_id_seq OWNER TO postgres;

--
-- TOC entry 3756 (class 0 OID 0)
-- Dependencies: 236
-- Name: dom_usu_dom_id_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_domi; Owner: postgres
--

ALTER SEQUENCE usuarios_domi.dom_usu_dom_id_seq OWNED BY usuarios_domi.dom_usu.dom_id;


--
-- TOC entry 237 (class 1259 OID 26311)
-- Name: dom_usu_dom_parr_seq; Type: SEQUENCE; Schema: usuarios_domi; Owner: postgres
--

CREATE SEQUENCE usuarios_domi.dom_usu_dom_parr_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_domi.dom_usu_dom_parr_seq OWNER TO postgres;

--
-- TOC entry 3757 (class 0 OID 0)
-- Dependencies: 237
-- Name: dom_usu_dom_parr_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_domi; Owner: postgres
--

ALTER SEQUENCE usuarios_domi.dom_usu_dom_parr_seq OWNED BY usuarios_domi.dom_usu.dom_parr;


--
-- TOC entry 238 (class 1259 OID 26312)
-- Name: dom_usu_dom_usu_seq; Type: SEQUENCE; Schema: usuarios_domi; Owner: postgres
--

CREATE SEQUENCE usuarios_domi.dom_usu_dom_usu_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_domi.dom_usu_dom_usu_seq OWNER TO postgres;

--
-- TOC entry 3758 (class 0 OID 0)
-- Dependencies: 238
-- Name: dom_usu_dom_usu_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_domi; Owner: postgres
--

ALTER SEQUENCE usuarios_domi.dom_usu_dom_usu_seq OWNED BY usuarios_domi.dom_usu.dom_usu;


--
-- TOC entry 229 (class 1259 OID 26284)
-- Name: estados; Type: TABLE; Schema: usuarios_domi; Owner: postgres
--

CREATE TABLE usuarios_domi.estados (
    est_id bigint NOT NULL,
    estado character varying(100) NOT NULL
);


ALTER TABLE usuarios_domi.estados OWNER TO postgres;

--
-- TOC entry 3759 (class 0 OID 0)
-- Dependencies: 229
-- Name: TABLE estados; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON TABLE usuarios_domi.estados IS 'tabla para almacenar los estados, ej: ''Tachira''';


--
-- TOC entry 3760 (class 0 OID 0)
-- Dependencies: 229
-- Name: COLUMN estados.est_id; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.estados.est_id IS 'ID de cada estado';


--
-- TOC entry 3761 (class 0 OID 0)
-- Dependencies: 229
-- Name: COLUMN estados.estado; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.estados.estado IS 'campo para almacenar el nombre del estado';


--
-- TOC entry 228 (class 1259 OID 26283)
-- Name: estados_est_id_seq; Type: SEQUENCE; Schema: usuarios_domi; Owner: postgres
--

CREATE SEQUENCE usuarios_domi.estados_est_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_domi.estados_est_id_seq OWNER TO postgres;

--
-- TOC entry 3762 (class 0 OID 0)
-- Dependencies: 228
-- Name: estados_est_id_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_domi; Owner: postgres
--

ALTER SEQUENCE usuarios_domi.estados_est_id_seq OWNED BY usuarios_domi.estados.est_id;


--
-- TOC entry 232 (class 1259 OID 26292)
-- Name: muni; Type: TABLE; Schema: usuarios_domi; Owner: postgres
--

CREATE TABLE usuarios_domi.muni (
    mun_id bigint NOT NULL,
    mun character varying(100) NOT NULL,
    mun_est bigint NOT NULL
);


ALTER TABLE usuarios_domi.muni OWNER TO postgres;

--
-- TOC entry 3763 (class 0 OID 0)
-- Dependencies: 232
-- Name: TABLE muni; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON TABLE usuarios_domi.muni IS 'tabla para almacenar los municipios, ej: ''San Cristobal''';


--
-- TOC entry 3764 (class 0 OID 0)
-- Dependencies: 232
-- Name: COLUMN muni.mun_id; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.muni.mun_id IS 'ID para cada municipio';


--
-- TOC entry 3765 (class 0 OID 0)
-- Dependencies: 232
-- Name: COLUMN muni.mun; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.muni.mun IS 'campo para almacenar el nombre del municipio, ej: ''Cordoba''';


--
-- TOC entry 3766 (class 0 OID 0)
-- Dependencies: 232
-- Name: COLUMN muni.mun_est; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.muni.mun_est IS 'campo para almacenar el ID del estado correspondiente al municipio';


--
-- TOC entry 231 (class 1259 OID 26291)
-- Name: muni_mun_est_seq; Type: SEQUENCE; Schema: usuarios_domi; Owner: postgres
--

CREATE SEQUENCE usuarios_domi.muni_mun_est_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_domi.muni_mun_est_seq OWNER TO postgres;

--
-- TOC entry 3767 (class 0 OID 0)
-- Dependencies: 231
-- Name: muni_mun_est_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_domi; Owner: postgres
--

ALTER SEQUENCE usuarios_domi.muni_mun_est_seq OWNED BY usuarios_domi.muni.mun_est;


--
-- TOC entry 230 (class 1259 OID 26290)
-- Name: muni_mun_id_seq; Type: SEQUENCE; Schema: usuarios_domi; Owner: postgres
--

CREATE SEQUENCE usuarios_domi.muni_mun_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_domi.muni_mun_id_seq OWNER TO postgres;

--
-- TOC entry 3768 (class 0 OID 0)
-- Dependencies: 230
-- Name: muni_mun_id_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_domi; Owner: postgres
--

ALTER SEQUENCE usuarios_domi.muni_mun_id_seq OWNED BY usuarios_domi.muni.mun_id;


--
-- TOC entry 235 (class 1259 OID 26301)
-- Name: parro; Type: TABLE; Schema: usuarios_domi; Owner: postgres
--

CREATE TABLE usuarios_domi.parro (
    parr_id bigint NOT NULL,
    parro character varying NOT NULL,
    parr_mun bigint NOT NULL
);


ALTER TABLE usuarios_domi.parro OWNER TO postgres;

--
-- TOC entry 3769 (class 0 OID 0)
-- Dependencies: 235
-- Name: TABLE parro; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON TABLE usuarios_domi.parro IS 'tabla para almacenar la parroquia de los usuarios';


--
-- TOC entry 3770 (class 0 OID 0)
-- Dependencies: 235
-- Name: COLUMN parro.parr_id; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.parro.parr_id IS 'ID para cada parroquia';


--
-- TOC entry 3771 (class 0 OID 0)
-- Dependencies: 235
-- Name: COLUMN parro.parro; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.parro.parro IS 'campo para almacenar los nombres de las parroquias';


--
-- TOC entry 3772 (class 0 OID 0)
-- Dependencies: 235
-- Name: COLUMN parro.parr_mun; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON COLUMN usuarios_domi.parro.parr_mun IS 'campo para almacenar el ID del municipio correspondiente';


--
-- TOC entry 233 (class 1259 OID 26299)
-- Name: parro_parr_id_seq; Type: SEQUENCE; Schema: usuarios_domi; Owner: postgres
--

CREATE SEQUENCE usuarios_domi.parro_parr_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_domi.parro_parr_id_seq OWNER TO postgres;

--
-- TOC entry 3773 (class 0 OID 0)
-- Dependencies: 233
-- Name: parro_parr_id_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_domi; Owner: postgres
--

ALTER SEQUENCE usuarios_domi.parro_parr_id_seq OWNED BY usuarios_domi.parro.parr_id;


--
-- TOC entry 234 (class 1259 OID 26300)
-- Name: parro_parr_mun_seq; Type: SEQUENCE; Schema: usuarios_domi; Owner: postgres
--

CREATE SEQUENCE usuarios_domi.parro_parr_mun_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_domi.parro_parr_mun_seq OWNER TO postgres;

--
-- TOC entry 3774 (class 0 OID 0)
-- Dependencies: 234
-- Name: parro_parr_mun_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_domi; Owner: postgres
--

ALTER SEQUENCE usuarios_domi.parro_parr_mun_seq OWNED BY usuarios_domi.parro.parr_mun;


--
-- TOC entry 227 (class 1259 OID 26277)
-- Name: roles_usu; Type: TABLE; Schema: usuarios_seg; Owner: postgres
--

CREATE TABLE usuarios_seg.roles_usu (
    rol_id bigint NOT NULL,
    rol character varying(30) NOT NULL,
    rol_des character varying(255)
);


ALTER TABLE usuarios_seg.roles_usu OWNER TO postgres;

--
-- TOC entry 3775 (class 0 OID 0)
-- Dependencies: 227
-- Name: TABLE roles_usu; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON TABLE usuarios_seg.roles_usu IS 'tabla para almacenar los roles de los usuarios, ej: ''admin'', ''cliente''';


--
-- TOC entry 3776 (class 0 OID 0)
-- Dependencies: 227
-- Name: COLUMN roles_usu.rol_id; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON COLUMN usuarios_seg.roles_usu.rol_id IS 'ID del rol';


--
-- TOC entry 3777 (class 0 OID 0)
-- Dependencies: 227
-- Name: COLUMN roles_usu.rol; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON COLUMN usuarios_seg.roles_usu.rol IS 'campo para almacenar el nombre del rol';


--
-- TOC entry 3778 (class 0 OID 0)
-- Dependencies: 227
-- Name: COLUMN roles_usu.rol_des; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON COLUMN usuarios_seg.roles_usu.rol_des IS 'campo para almacenar la descripcion del rol (que desempena)';


--
-- TOC entry 226 (class 1259 OID 26276)
-- Name: roles_usu_rol_id_seq; Type: SEQUENCE; Schema: usuarios_seg; Owner: postgres
--

CREATE SEQUENCE usuarios_seg.roles_usu_rol_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_seg.roles_usu_rol_id_seq OWNER TO postgres;

--
-- TOC entry 3779 (class 0 OID 0)
-- Dependencies: 226
-- Name: roles_usu_rol_id_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_seg; Owner: postgres
--

ALTER SEQUENCE usuarios_seg.roles_usu_rol_id_seq OWNED BY usuarios_seg.roles_usu.rol_id;


--
-- TOC entry 225 (class 1259 OID 26266)
-- Name: seg_usu; Type: TABLE; Schema: usuarios_seg; Owner: postgres
--

CREATE TABLE usuarios_seg.seg_usu (
    seg_id bigint NOT NULL,
    seg_act "char" DEFAULT 'A'::"char" NOT NULL,
    seg_ini timestamp with time zone NOT NULL,
    seg_cod integer,
    seg_rol bigint NOT NULL,
    seg_usu bigint NOT NULL,
    CONSTRAINT seg_act_check CHECK ((seg_act = ANY (ARRAY['A'::"char", 'I'::"char", 'B'::"char", 'C'::"char"])))
);


ALTER TABLE usuarios_seg.seg_usu OWNER TO postgres;

--
-- TOC entry 3780 (class 0 OID 0)
-- Dependencies: 225
-- Name: TABLE seg_usu; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON TABLE usuarios_seg.seg_usu IS 'tabla para manejar la logica de seguridad de los usuarios';


--
-- TOC entry 3781 (class 0 OID 0)
-- Dependencies: 225
-- Name: COLUMN seg_usu.seg_id; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON COLUMN usuarios_seg.seg_usu.seg_id IS 'ID de seguridad para cada usuario';


--
-- TOC entry 3782 (class 0 OID 0)
-- Dependencies: 225
-- Name: COLUMN seg_usu.seg_act; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON COLUMN usuarios_seg.seg_usu.seg_act IS 'campo para verificar si un usuario esta activo, ej: ''A'' (activo)';


--
-- TOC entry 3783 (class 0 OID 0)
-- Dependencies: 225
-- Name: COLUMN seg_usu.seg_ini; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON COLUMN usuarios_seg.seg_usu.seg_ini IS 'campo para almacenar los ultimos inicios de sesion del usuario, ej: ''10/08/2025 06:51 am''';


--
-- TOC entry 3784 (class 0 OID 0)
-- Dependencies: 225
-- Name: COLUMN seg_usu.seg_cod; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON COLUMN usuarios_seg.seg_usu.seg_cod IS 'campo para almacenar los codigos de seguridad, ej: ''123456''';


--
-- TOC entry 3785 (class 0 OID 0)
-- Dependencies: 225
-- Name: COLUMN seg_usu.seg_rol; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON COLUMN usuarios_seg.seg_usu.seg_rol IS 'campo para almacenar el rol asignado al usuario';


--
-- TOC entry 3786 (class 0 OID 0)
-- Dependencies: 225
-- Name: COLUMN seg_usu.seg_usu; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON COLUMN usuarios_seg.seg_usu.seg_usu IS 'campo para almacenar el ID del usuario correspondiente';


--
-- TOC entry 3787 (class 0 OID 0)
-- Dependencies: 225
-- Name: CONSTRAINT seg_act_check ON seg_usu; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON CONSTRAINT seg_act_check ON usuarios_seg.seg_usu IS 'tipos de caracteres a recibir en este campo
A (activo)
I (inactivo)
B (bloqueado)
C (congelado)';


--
-- TOC entry 222 (class 1259 OID 26263)
-- Name: seg_usu_seg_id_seq; Type: SEQUENCE; Schema: usuarios_seg; Owner: postgres
--

CREATE SEQUENCE usuarios_seg.seg_usu_seg_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_seg.seg_usu_seg_id_seq OWNER TO postgres;

--
-- TOC entry 3788 (class 0 OID 0)
-- Dependencies: 222
-- Name: seg_usu_seg_id_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_seg; Owner: postgres
--

ALTER SEQUENCE usuarios_seg.seg_usu_seg_id_seq OWNED BY usuarios_seg.seg_usu.seg_id;


--
-- TOC entry 223 (class 1259 OID 26264)
-- Name: seg_usu_seg_rol_seq; Type: SEQUENCE; Schema: usuarios_seg; Owner: postgres
--

CREATE SEQUENCE usuarios_seg.seg_usu_seg_rol_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_seg.seg_usu_seg_rol_seq OWNER TO postgres;

--
-- TOC entry 3789 (class 0 OID 0)
-- Dependencies: 223
-- Name: seg_usu_seg_rol_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_seg; Owner: postgres
--

ALTER SEQUENCE usuarios_seg.seg_usu_seg_rol_seq OWNED BY usuarios_seg.seg_usu.seg_rol;


--
-- TOC entry 224 (class 1259 OID 26265)
-- Name: seg_usu_seg_usu_seq; Type: SEQUENCE; Schema: usuarios_seg; Owner: postgres
--

CREATE SEQUENCE usuarios_seg.seg_usu_seg_usu_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE usuarios_seg.seg_usu_seg_usu_seq OWNER TO postgres;

--
-- TOC entry 3790 (class 0 OID 0)
-- Dependencies: 224
-- Name: seg_usu_seg_usu_seq; Type: SEQUENCE OWNED BY; Schema: usuarios_seg; Owner: postgres
--

ALTER SEQUENCE usuarios_seg.seg_usu_seg_usu_seq OWNED BY usuarios_seg.seg_usu.seg_usu;


--
-- TOC entry 3447 (class 2604 OID 26256)
-- Name: usuarios usu_id; Type: DEFAULT; Schema: usuarios_dat; Owner: postgres
--

ALTER TABLE ONLY usuarios_dat.usuarios ALTER COLUMN usu_id SET DEFAULT nextval('usuarios_dat.usuarios_usu_id_seq'::regclass);


--
-- TOC entry 3458 (class 2604 OID 26316)
-- Name: dom_usu dom_id; Type: DEFAULT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.dom_usu ALTER COLUMN dom_id SET DEFAULT nextval('usuarios_domi.dom_usu_dom_id_seq'::regclass);


--
-- TOC entry 3459 (class 2604 OID 26317)
-- Name: dom_usu dom_parr; Type: DEFAULT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.dom_usu ALTER COLUMN dom_parr SET DEFAULT nextval('usuarios_domi.dom_usu_dom_parr_seq'::regclass);


--
-- TOC entry 3460 (class 2604 OID 26318)
-- Name: dom_usu dom_usu; Type: DEFAULT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.dom_usu ALTER COLUMN dom_usu SET DEFAULT nextval('usuarios_domi.dom_usu_dom_usu_seq'::regclass);


--
-- TOC entry 3453 (class 2604 OID 26287)
-- Name: estados est_id; Type: DEFAULT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.estados ALTER COLUMN est_id SET DEFAULT nextval('usuarios_domi.estados_est_id_seq'::regclass);


--
-- TOC entry 3454 (class 2604 OID 26295)
-- Name: muni mun_id; Type: DEFAULT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.muni ALTER COLUMN mun_id SET DEFAULT nextval('usuarios_domi.muni_mun_id_seq'::regclass);


--
-- TOC entry 3455 (class 2604 OID 26296)
-- Name: muni mun_est; Type: DEFAULT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.muni ALTER COLUMN mun_est SET DEFAULT nextval('usuarios_domi.muni_mun_est_seq'::regclass);


--
-- TOC entry 3456 (class 2604 OID 26304)
-- Name: parro parr_id; Type: DEFAULT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.parro ALTER COLUMN parr_id SET DEFAULT nextval('usuarios_domi.parro_parr_id_seq'::regclass);


--
-- TOC entry 3457 (class 2604 OID 26305)
-- Name: parro parr_mun; Type: DEFAULT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.parro ALTER COLUMN parr_mun SET DEFAULT nextval('usuarios_domi.parro_parr_mun_seq'::regclass);


--
-- TOC entry 3452 (class 2604 OID 26280)
-- Name: roles_usu rol_id; Type: DEFAULT; Schema: usuarios_seg; Owner: postgres
--

ALTER TABLE ONLY usuarios_seg.roles_usu ALTER COLUMN rol_id SET DEFAULT nextval('usuarios_seg.roles_usu_rol_id_seq'::regclass);


--
-- TOC entry 3448 (class 2604 OID 26269)
-- Name: seg_usu seg_id; Type: DEFAULT; Schema: usuarios_seg; Owner: postgres
--

ALTER TABLE ONLY usuarios_seg.seg_usu ALTER COLUMN seg_id SET DEFAULT nextval('usuarios_seg.seg_usu_seg_id_seq'::regclass);


--
-- TOC entry 3450 (class 2604 OID 26271)
-- Name: seg_usu seg_rol; Type: DEFAULT; Schema: usuarios_seg; Owner: postgres
--

ALTER TABLE ONLY usuarios_seg.seg_usu ALTER COLUMN seg_rol SET DEFAULT nextval('usuarios_seg.seg_usu_seg_rol_seq'::regclass);


--
-- TOC entry 3451 (class 2604 OID 26272)
-- Name: seg_usu seg_usu; Type: DEFAULT; Schema: usuarios_seg; Owner: postgres
--

ALTER TABLE ONLY usuarios_seg.seg_usu ALTER COLUMN seg_usu SET DEFAULT nextval('usuarios_seg.seg_usu_seg_usu_seq'::regclass);


--
-- TOC entry 3721 (class 0 OID 26572)
-- Dependencies: 247
-- Data for Name: auth_group; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.auth_group (id, name) FROM stdin;
\.


--
-- TOC entry 3723 (class 0 OID 26580)
-- Dependencies: 249
-- Data for Name: auth_group_permissions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.auth_group_permissions (id, group_id, permission_id) FROM stdin;
\.


--
-- TOC entry 3719 (class 0 OID 26566)
-- Dependencies: 245
-- Data for Name: auth_permission; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.auth_permission (id, name, content_type_id, codename) FROM stdin;
1	Can add log entry	1	add_logentry
2	Can change log entry	1	change_logentry
3	Can delete log entry	1	delete_logentry
4	Can view log entry	1	view_logentry
5	Can add permission	2	add_permission
6	Can change permission	2	change_permission
7	Can delete permission	2	delete_permission
8	Can view permission	2	view_permission
9	Can add group	3	add_group
10	Can change group	3	change_group
11	Can delete group	3	delete_group
12	Can view group	3	view_group
13	Can add user	4	add_user
14	Can change user	4	change_user
15	Can delete user	4	delete_user
16	Can view user	4	view_user
17	Can add content type	5	add_contenttype
18	Can change content type	5	change_contenttype
19	Can delete content type	5	delete_contenttype
20	Can view content type	5	view_contenttype
21	Can add session	6	add_session
22	Can change session	6	change_session
23	Can delete session	6	delete_session
24	Can view session	6	view_session
\.


--
-- TOC entry 3725 (class 0 OID 26586)
-- Dependencies: 251
-- Data for Name: auth_user; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.auth_user (id, password, last_login, is_superuser, username, first_name, last_name, email, is_staff, is_active, date_joined) FROM stdin;
\.


--
-- TOC entry 3727 (class 0 OID 26594)
-- Dependencies: 253
-- Data for Name: auth_user_groups; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.auth_user_groups (id, user_id, group_id) FROM stdin;
\.


--
-- TOC entry 3729 (class 0 OID 26600)
-- Dependencies: 255
-- Data for Name: auth_user_user_permissions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.auth_user_user_permissions (id, user_id, permission_id) FROM stdin;
\.


--
-- TOC entry 3731 (class 0 OID 26658)
-- Dependencies: 257
-- Data for Name: django_admin_log; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.django_admin_log (id, action_time, object_id, object_repr, action_flag, change_message, content_type_id, user_id) FROM stdin;
\.


--
-- TOC entry 3717 (class 0 OID 26558)
-- Dependencies: 243
-- Data for Name: django_content_type; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.django_content_type (id, app_label, model) FROM stdin;
1	admin	logentry
2	auth	permission
3	auth	group
4	auth	user
5	contenttypes	contenttype
6	sessions	session
\.


--
-- TOC entry 3715 (class 0 OID 26550)
-- Dependencies: 241
-- Data for Name: django_migrations; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.django_migrations (id, app, name, applied) FROM stdin;
1	contenttypes	0001_initial	2025-08-19 00:12:07.517067-04
2	auth	0001_initial	2025-08-19 00:12:07.808288-04
3	admin	0001_initial	2025-08-19 00:12:07.889244-04
4	admin	0002_logentry_remove_auto_add	2025-08-19 00:12:07.914491-04
5	admin	0003_logentry_add_action_flag_choices	2025-08-19 00:12:07.941352-04
6	contenttypes	0002_remove_content_type_name	2025-08-19 00:12:07.99707-04
7	auth	0002_alter_permission_name_max_length	2025-08-19 00:12:08.0215-04
8	auth	0003_alter_user_email_max_length	2025-08-19 00:12:08.044105-04
9	auth	0004_alter_user_username_opts	2025-08-19 00:12:08.064344-04
10	auth	0005_alter_user_last_login_null	2025-08-19 00:12:08.085316-04
11	auth	0006_require_contenttypes_0002	2025-08-19 00:12:08.090645-04
12	auth	0007_alter_validators_add_error_messages	2025-08-19 00:12:08.112245-04
13	auth	0008_alter_user_username_max_length	2025-08-19 00:12:08.148904-04
14	auth	0009_alter_user_last_name_max_length	2025-08-19 00:12:08.172515-04
15	auth	0010_alter_group_name_max_length	2025-08-19 00:12:08.204061-04
16	auth	0011_update_proxy_permissions	2025-08-19 00:12:08.22357-04
17	auth	0012_alter_user_first_name_max_length	2025-08-19 00:12:08.246585-04
18	sessions	0001_initial	2025-08-19 00:12:08.297977-04
\.


--
-- TOC entry 3732 (class 0 OID 26686)
-- Dependencies: 258
-- Data for Name: django_session; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.django_session (session_key, session_data, expire_date) FROM stdin;
508ih6gakgjj8gv6hyk2kq7kyjqtdzrh	eyJ1c2VyX2lkIjo0LCJ1c2VyX3JvbCI6ImFkbWluIn0:1uoDn1:KtWhTs70OGIL58aZGb7jG39mtqWqAwdE8MQRyI_d__I	2025-09-02 00:17:39.53177-04
\.


--
-- TOC entry 3695 (class 0 OID 26253)
-- Dependencies: 221
-- Data for Name: usuarios; Type: TABLE DATA; Schema: usuarios_dat; Owner: postgres
--

COPY usuarios_dat.usuarios (usu_id, usu_nom, usu_apell, usu_fn, usu_corr, usu_cla) FROM stdin;
6	abrahan jose	colmenares antolinez	2005-04-16	colmenaresabrahan555f@gmail.com	$2a$06$jr856XVKMRrlxpfAmIzyLugYvOaYw0Xk2DYVWR7n8a6A73wiBJuCu
7	jose	perez	2025-08-13	juanperez@gmail.com	$2a$06$VKEh7m1WgxUbONQBpcOm0OvtUnSC4BpS7DeylH2dvDa727nklC1fK
5	guillermo	jimenez	2005-04-16	colmenaresabrahan55f@gmail.com	$2a$06$EjUmAblHixNqXlWhbIFISuTjJ9/3fOYWZ6W4i22wJ7YsH/6GrkCla
4	abrahan	colmenares	2005-04-16	colmenaresabrahan5f@gmail.com	$2a$06$kLTt4KRiDvcxlAmO0Gohb.NxA4BNVMS1c6TZ8GpCy2jgl1PPGtQJK
\.


--
-- TOC entry 3713 (class 0 OID 26313)
-- Dependencies: 239
-- Data for Name: dom_usu; Type: TABLE DATA; Schema: usuarios_domi; Owner: postgres
--

COPY usuarios_domi.dom_usu (dom_id, dom_com, dom_parr, dom_usu) FROM stdin;
\.


--
-- TOC entry 3703 (class 0 OID 26284)
-- Dependencies: 229
-- Data for Name: estados; Type: TABLE DATA; Schema: usuarios_domi; Owner: postgres
--

COPY usuarios_domi.estados (est_id, estado) FROM stdin;
1	tachira
\.


--
-- TOC entry 3706 (class 0 OID 26292)
-- Dependencies: 232
-- Data for Name: muni; Type: TABLE DATA; Schema: usuarios_domi; Owner: postgres
--

COPY usuarios_domi.muni (mun_id, mun, mun_est) FROM stdin;
1	san cristobal	1
\.


--
-- TOC entry 3709 (class 0 OID 26301)
-- Dependencies: 235
-- Data for Name: parro; Type: TABLE DATA; Schema: usuarios_domi; Owner: postgres
--

COPY usuarios_domi.parro (parr_id, parro, parr_mun) FROM stdin;
1	la concondia	1
\.


--
-- TOC entry 3701 (class 0 OID 26277)
-- Dependencies: 227
-- Data for Name: roles_usu; Type: TABLE DATA; Schema: usuarios_seg; Owner: postgres
--

COPY usuarios_seg.roles_usu (rol_id, rol, rol_des) FROM stdin;
1	admin	administradores principales
2	client	clientes regulares
\.


--
-- TOC entry 3699 (class 0 OID 26266)
-- Dependencies: 225
-- Data for Name: seg_usu; Type: TABLE DATA; Schema: usuarios_seg; Owner: postgres
--

COPY usuarios_seg.seg_usu (seg_id, seg_act, seg_ini, seg_cod, seg_rol, seg_usu) FROM stdin;
1	A	2025-08-13 15:01:35.508449-04	\N	1	4
2	A	2025-08-19 20:41:05.130492-04	\N	2	5
3	A	2025-08-19 21:04:56.197526-04	\N	2	6
4	A	2025-08-19 21:08:25.87481-04	\N	2	7
\.


--
-- TOC entry 3791 (class 0 OID 0)
-- Dependencies: 246
-- Name: auth_group_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.auth_group_id_seq', 1, false);


--
-- TOC entry 3792 (class 0 OID 0)
-- Dependencies: 248
-- Name: auth_group_permissions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.auth_group_permissions_id_seq', 1, false);


--
-- TOC entry 3793 (class 0 OID 0)
-- Dependencies: 244
-- Name: auth_permission_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.auth_permission_id_seq', 24, true);


--
-- TOC entry 3794 (class 0 OID 0)
-- Dependencies: 252
-- Name: auth_user_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.auth_user_groups_id_seq', 1, false);


--
-- TOC entry 3795 (class 0 OID 0)
-- Dependencies: 250
-- Name: auth_user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.auth_user_id_seq', 1, false);


--
-- TOC entry 3796 (class 0 OID 0)
-- Dependencies: 254
-- Name: auth_user_user_permissions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.auth_user_user_permissions_id_seq', 1, false);


--
-- TOC entry 3797 (class 0 OID 0)
-- Dependencies: 256
-- Name: django_admin_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.django_admin_log_id_seq', 1, false);


--
-- TOC entry 3798 (class 0 OID 0)
-- Dependencies: 242
-- Name: django_content_type_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.django_content_type_id_seq', 6, true);


--
-- TOC entry 3799 (class 0 OID 0)
-- Dependencies: 240
-- Name: django_migrations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.django_migrations_id_seq', 18, true);


--
-- TOC entry 3800 (class 0 OID 0)
-- Dependencies: 220
-- Name: usuarios_usu_id_seq; Type: SEQUENCE SET; Schema: usuarios_dat; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_dat.usuarios_usu_id_seq', 7, true);


--
-- TOC entry 3801 (class 0 OID 0)
-- Dependencies: 236
-- Name: dom_usu_dom_id_seq; Type: SEQUENCE SET; Schema: usuarios_domi; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_domi.dom_usu_dom_id_seq', 1, false);


--
-- TOC entry 3802 (class 0 OID 0)
-- Dependencies: 237
-- Name: dom_usu_dom_parr_seq; Type: SEQUENCE SET; Schema: usuarios_domi; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_domi.dom_usu_dom_parr_seq', 1, false);


--
-- TOC entry 3803 (class 0 OID 0)
-- Dependencies: 238
-- Name: dom_usu_dom_usu_seq; Type: SEQUENCE SET; Schema: usuarios_domi; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_domi.dom_usu_dom_usu_seq', 1, false);


--
-- TOC entry 3804 (class 0 OID 0)
-- Dependencies: 228
-- Name: estados_est_id_seq; Type: SEQUENCE SET; Schema: usuarios_domi; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_domi.estados_est_id_seq', 1, true);


--
-- TOC entry 3805 (class 0 OID 0)
-- Dependencies: 231
-- Name: muni_mun_est_seq; Type: SEQUENCE SET; Schema: usuarios_domi; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_domi.muni_mun_est_seq', 1, false);


--
-- TOC entry 3806 (class 0 OID 0)
-- Dependencies: 230
-- Name: muni_mun_id_seq; Type: SEQUENCE SET; Schema: usuarios_domi; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_domi.muni_mun_id_seq', 1, true);


--
-- TOC entry 3807 (class 0 OID 0)
-- Dependencies: 233
-- Name: parro_parr_id_seq; Type: SEQUENCE SET; Schema: usuarios_domi; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_domi.parro_parr_id_seq', 1, true);


--
-- TOC entry 3808 (class 0 OID 0)
-- Dependencies: 234
-- Name: parro_parr_mun_seq; Type: SEQUENCE SET; Schema: usuarios_domi; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_domi.parro_parr_mun_seq', 1, false);


--
-- TOC entry 3809 (class 0 OID 0)
-- Dependencies: 226
-- Name: roles_usu_rol_id_seq; Type: SEQUENCE SET; Schema: usuarios_seg; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_seg.roles_usu_rol_id_seq', 2, true);


--
-- TOC entry 3810 (class 0 OID 0)
-- Dependencies: 222
-- Name: seg_usu_seg_id_seq; Type: SEQUENCE SET; Schema: usuarios_seg; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_seg.seg_usu_seg_id_seq', 4, true);


--
-- TOC entry 3811 (class 0 OID 0)
-- Dependencies: 223
-- Name: seg_usu_seg_rol_seq; Type: SEQUENCE SET; Schema: usuarios_seg; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_seg.seg_usu_seg_rol_seq', 1, false);


--
-- TOC entry 3812 (class 0 OID 0)
-- Dependencies: 224
-- Name: seg_usu_seg_usu_seq; Type: SEQUENCE SET; Schema: usuarios_seg; Owner: postgres
--

SELECT pg_catalog.setval('usuarios_seg.seg_usu_seg_usu_seq', 1, false);


--
-- TOC entry 3502 (class 2606 OID 26684)
-- Name: auth_group auth_group_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_name_key UNIQUE (name);


--
-- TOC entry 3507 (class 2606 OID 26615)
-- Name: auth_group_permissions auth_group_permissions_group_id_permission_id_0cd325b0_uniq; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_group_id_permission_id_0cd325b0_uniq UNIQUE (group_id, permission_id);


--
-- TOC entry 3510 (class 2606 OID 26584)
-- Name: auth_group_permissions auth_group_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_pkey PRIMARY KEY (id);


--
-- TOC entry 3504 (class 2606 OID 26576)
-- Name: auth_group auth_group_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_pkey PRIMARY KEY (id);


--
-- TOC entry 3497 (class 2606 OID 26606)
-- Name: auth_permission auth_permission_content_type_id_codename_01ab375a_uniq; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_content_type_id_codename_01ab375a_uniq UNIQUE (content_type_id, codename);


--
-- TOC entry 3499 (class 2606 OID 26570)
-- Name: auth_permission auth_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_pkey PRIMARY KEY (id);


--
-- TOC entry 3518 (class 2606 OID 26598)
-- Name: auth_user_groups auth_user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_pkey PRIMARY KEY (id);


--
-- TOC entry 3521 (class 2606 OID 26630)
-- Name: auth_user_groups auth_user_groups_user_id_group_id_94350c0c_uniq; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_user_id_group_id_94350c0c_uniq UNIQUE (user_id, group_id);


--
-- TOC entry 3512 (class 2606 OID 26590)
-- Name: auth_user auth_user_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user
    ADD CONSTRAINT auth_user_pkey PRIMARY KEY (id);


--
-- TOC entry 3524 (class 2606 OID 26604)
-- Name: auth_user_user_permissions auth_user_user_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_pkey PRIMARY KEY (id);


--
-- TOC entry 3527 (class 2606 OID 26644)
-- Name: auth_user_user_permissions auth_user_user_permissions_user_id_permission_id_14a6b632_uniq; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_user_id_permission_id_14a6b632_uniq UNIQUE (user_id, permission_id);


--
-- TOC entry 3515 (class 2606 OID 26679)
-- Name: auth_user auth_user_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user
    ADD CONSTRAINT auth_user_username_key UNIQUE (username);


--
-- TOC entry 3530 (class 2606 OID 26665)
-- Name: django_admin_log django_admin_log_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_pkey PRIMARY KEY (id);


--
-- TOC entry 3492 (class 2606 OID 26564)
-- Name: django_content_type django_content_type_app_label_model_76bd3d3b_uniq; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.django_content_type
    ADD CONSTRAINT django_content_type_app_label_model_76bd3d3b_uniq UNIQUE (app_label, model);


--
-- TOC entry 3494 (class 2606 OID 26562)
-- Name: django_content_type django_content_type_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.django_content_type
    ADD CONSTRAINT django_content_type_pkey PRIMARY KEY (id);


--
-- TOC entry 3490 (class 2606 OID 26556)
-- Name: django_migrations django_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.django_migrations
    ADD CONSTRAINT django_migrations_pkey PRIMARY KEY (id);


--
-- TOC entry 3534 (class 2606 OID 26692)
-- Name: django_session django_session_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.django_session
    ADD CONSTRAINT django_session_pkey PRIMARY KEY (session_key);


--
-- TOC entry 3467 (class 2606 OID 26260)
-- Name: usuarios usu_id_pk; Type: CONSTRAINT; Schema: usuarios_dat; Owner: postgres
--

ALTER TABLE ONLY usuarios_dat.usuarios
    ADD CONSTRAINT usu_id_pk PRIMARY KEY (usu_id);


--
-- TOC entry 3813 (class 0 OID 0)
-- Dependencies: 3467
-- Name: CONSTRAINT usu_id_pk ON usuarios; Type: COMMENT; Schema: usuarios_dat; Owner: postgres
--

COMMENT ON CONSTRAINT usu_id_pk ON usuarios_dat.usuarios IS 'llave primaria para el campo usu_id';


--
-- TOC entry 3486 (class 2606 OID 26322)
-- Name: dom_usu dom_id_pk; Type: CONSTRAINT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.dom_usu
    ADD CONSTRAINT dom_id_pk PRIMARY KEY (dom_id);


--
-- TOC entry 3814 (class 0 OID 0)
-- Dependencies: 3486
-- Name: CONSTRAINT dom_id_pk ON dom_usu; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON CONSTRAINT dom_id_pk ON usuarios_domi.dom_usu IS 'llave primaria';


--
-- TOC entry 3478 (class 2606 OID 26289)
-- Name: estados est_id_pk; Type: CONSTRAINT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.estados
    ADD CONSTRAINT est_id_pk PRIMARY KEY (est_id);


--
-- TOC entry 3815 (class 0 OID 0)
-- Dependencies: 3478
-- Name: CONSTRAINT est_id_pk ON estados; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON CONSTRAINT est_id_pk ON usuarios_domi.estados IS 'llave primaria para el id del estado';


--
-- TOC entry 3481 (class 2606 OID 26298)
-- Name: muni mun_id_pk; Type: CONSTRAINT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.muni
    ADD CONSTRAINT mun_id_pk PRIMARY KEY (mun_id);


--
-- TOC entry 3816 (class 0 OID 0)
-- Dependencies: 3481
-- Name: CONSTRAINT mun_id_pk ON muni; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON CONSTRAINT mun_id_pk ON usuarios_domi.muni IS 'llave primaria';


--
-- TOC entry 3484 (class 2606 OID 26309)
-- Name: parro parr_id_pk; Type: CONSTRAINT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.parro
    ADD CONSTRAINT parr_id_pk PRIMARY KEY (parr_id);


--
-- TOC entry 3817 (class 0 OID 0)
-- Dependencies: 3484
-- Name: CONSTRAINT parr_id_pk ON parro; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON CONSTRAINT parr_id_pk ON usuarios_domi.parro IS 'llave primaria';


--
-- TOC entry 3475 (class 2606 OID 26282)
-- Name: roles_usu rol_id_pk; Type: CONSTRAINT; Schema: usuarios_seg; Owner: postgres
--

ALTER TABLE ONLY usuarios_seg.roles_usu
    ADD CONSTRAINT rol_id_pk PRIMARY KEY (rol_id);


--
-- TOC entry 3818 (class 0 OID 0)
-- Dependencies: 3475
-- Name: CONSTRAINT rol_id_pk ON roles_usu; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON CONSTRAINT rol_id_pk ON usuarios_seg.roles_usu IS 'llave primaria';


--
-- TOC entry 3473 (class 2606 OID 26275)
-- Name: seg_usu seg_id_pk; Type: CONSTRAINT; Schema: usuarios_seg; Owner: postgres
--

ALTER TABLE ONLY usuarios_seg.seg_usu
    ADD CONSTRAINT seg_id_pk PRIMARY KEY (seg_id);


--
-- TOC entry 3819 (class 0 OID 0)
-- Dependencies: 3473
-- Name: CONSTRAINT seg_id_pk ON seg_usu; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON CONSTRAINT seg_id_pk ON usuarios_seg.seg_usu IS 'llave primaria';


--
-- TOC entry 3500 (class 1259 OID 26685)
-- Name: auth_group_name_a6ea08ec_like; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX auth_group_name_a6ea08ec_like ON public.auth_group USING btree (name varchar_pattern_ops);


--
-- TOC entry 3505 (class 1259 OID 26626)
-- Name: auth_group_permissions_group_id_b120cbf9; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX auth_group_permissions_group_id_b120cbf9 ON public.auth_group_permissions USING btree (group_id);


--
-- TOC entry 3508 (class 1259 OID 26627)
-- Name: auth_group_permissions_permission_id_84c5c92e; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX auth_group_permissions_permission_id_84c5c92e ON public.auth_group_permissions USING btree (permission_id);


--
-- TOC entry 3495 (class 1259 OID 26612)
-- Name: auth_permission_content_type_id_2f476e4b; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX auth_permission_content_type_id_2f476e4b ON public.auth_permission USING btree (content_type_id);


--
-- TOC entry 3516 (class 1259 OID 26642)
-- Name: auth_user_groups_group_id_97559544; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX auth_user_groups_group_id_97559544 ON public.auth_user_groups USING btree (group_id);


--
-- TOC entry 3519 (class 1259 OID 26641)
-- Name: auth_user_groups_user_id_6a12ed8b; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX auth_user_groups_user_id_6a12ed8b ON public.auth_user_groups USING btree (user_id);


--
-- TOC entry 3522 (class 1259 OID 26656)
-- Name: auth_user_user_permissions_permission_id_1fbb5f2c; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX auth_user_user_permissions_permission_id_1fbb5f2c ON public.auth_user_user_permissions USING btree (permission_id);


--
-- TOC entry 3525 (class 1259 OID 26655)
-- Name: auth_user_user_permissions_user_id_a95ead1b; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX auth_user_user_permissions_user_id_a95ead1b ON public.auth_user_user_permissions USING btree (user_id);


--
-- TOC entry 3513 (class 1259 OID 26680)
-- Name: auth_user_username_6821ab7c_like; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX auth_user_username_6821ab7c_like ON public.auth_user USING btree (username varchar_pattern_ops);


--
-- TOC entry 3528 (class 1259 OID 26676)
-- Name: django_admin_log_content_type_id_c4bce8eb; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX django_admin_log_content_type_id_c4bce8eb ON public.django_admin_log USING btree (content_type_id);


--
-- TOC entry 3531 (class 1259 OID 26677)
-- Name: django_admin_log_user_id_c564eba6; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX django_admin_log_user_id_c564eba6 ON public.django_admin_log USING btree (user_id);


--
-- TOC entry 3532 (class 1259 OID 26694)
-- Name: django_session_expire_date_a5c62663; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX django_session_expire_date_a5c62663 ON public.django_session USING btree (expire_date);


--
-- TOC entry 3535 (class 1259 OID 26693)
-- Name: django_session_session_key_c0390e0f_like; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX django_session_session_key_c0390e0f_like ON public.django_session USING btree (session_key varchar_pattern_ops);


--
-- TOC entry 3463 (class 1259 OID 26443)
-- Name: idx_usuarios_email_lower; Type: INDEX; Schema: usuarios_dat; Owner: postgres
--

CREATE INDEX idx_usuarios_email_lower ON usuarios_dat.usuarios USING btree (lower((usu_corr)::text));


--
-- TOC entry 3464 (class 1259 OID 26442)
-- Name: idx_usuarios_nombre_trgm; Type: INDEX; Schema: usuarios_dat; Owner: postgres
--

CREATE INDEX idx_usuarios_nombre_trgm ON usuarios_dat.usuarios USING gin (((((usu_nom)::text || ' '::text) || (usu_apell)::text)) gin_trgm_ops);


--
-- TOC entry 3465 (class 1259 OID 26445)
-- Name: usu_corr_ci_uq; Type: INDEX; Schema: usuarios_dat; Owner: postgres
--

CREATE UNIQUE INDEX usu_corr_ci_uq ON usuarios_dat.usuarios USING btree (lower((usu_corr)::text));


--
-- TOC entry 3487 (class 1259 OID 26439)
-- Name: idx_dom_usu_user; Type: INDEX; Schema: usuarios_domi; Owner: postgres
--

CREATE INDEX idx_dom_usu_user ON usuarios_domi.dom_usu USING btree (dom_usu);


--
-- TOC entry 3488 (class 1259 OID 26440)
-- Name: idx_dom_usu_user_parr; Type: INDEX; Schema: usuarios_domi; Owner: postgres
--

CREATE INDEX idx_dom_usu_user_parr ON usuarios_domi.dom_usu USING btree (dom_usu, dom_parr);


--
-- TOC entry 3479 (class 1259 OID 26437)
-- Name: idx_muni_est; Type: INDEX; Schema: usuarios_domi; Owner: postgres
--

CREATE INDEX idx_muni_est ON usuarios_domi.muni USING btree (mun_est);


--
-- TOC entry 3482 (class 1259 OID 26438)
-- Name: idx_parro_mun; Type: INDEX; Schema: usuarios_domi; Owner: postgres
--

CREATE INDEX idx_parro_mun ON usuarios_domi.parro USING btree (parr_mun);


--
-- TOC entry 3468 (class 1259 OID 26444)
-- Name: idx_seg_usu_by_role_active; Type: INDEX; Schema: usuarios_seg; Owner: postgres
--

CREATE INDEX idx_seg_usu_by_role_active ON usuarios_seg.seg_usu USING btree (seg_rol) WHERE (seg_act = 'A'::"char");


--
-- TOC entry 3469 (class 1259 OID 26436)
-- Name: idx_seg_usu_seg_ini; Type: INDEX; Schema: usuarios_seg; Owner: postgres
--

CREATE INDEX idx_seg_usu_seg_ini ON usuarios_seg.seg_usu USING btree (seg_ini);


--
-- TOC entry 3470 (class 1259 OID 26435)
-- Name: idx_seg_usu_seg_rol; Type: INDEX; Schema: usuarios_seg; Owner: postgres
--

CREATE INDEX idx_seg_usu_seg_rol ON usuarios_seg.seg_usu USING btree (seg_rol);


--
-- TOC entry 3471 (class 1259 OID 26434)
-- Name: idx_seg_usu_seg_usu; Type: INDEX; Schema: usuarios_seg; Owner: postgres
--

CREATE INDEX idx_seg_usu_seg_usu ON usuarios_seg.seg_usu USING btree (seg_usu);


--
-- TOC entry 3476 (class 1259 OID 26441)
-- Name: ux_roles_usu_rol; Type: INDEX; Schema: usuarios_seg; Owner: postgres
--

CREATE UNIQUE INDEX ux_roles_usu_rol ON usuarios_seg.roles_usu USING btree (rol);


--
-- TOC entry 3543 (class 2606 OID 26621)
-- Name: auth_group_permissions auth_group_permissio_permission_id_84c5c92e_fk_auth_perm; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissio_permission_id_84c5c92e_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;


--
-- TOC entry 3544 (class 2606 OID 26616)
-- Name: auth_group_permissions auth_group_permissions_group_id_b120cbf9_fk_auth_group_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_group_permissions
    ADD CONSTRAINT auth_group_permissions_group_id_b120cbf9_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id) DEFERRABLE INITIALLY DEFERRED;


--
-- TOC entry 3542 (class 2606 OID 26607)
-- Name: auth_permission auth_permission_content_type_id_2f476e4b_fk_django_co; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_permission
    ADD CONSTRAINT auth_permission_content_type_id_2f476e4b_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- TOC entry 3545 (class 2606 OID 26636)
-- Name: auth_user_groups auth_user_groups_group_id_97559544_fk_auth_group_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_group_id_97559544_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES public.auth_group(id) DEFERRABLE INITIALLY DEFERRED;


--
-- TOC entry 3546 (class 2606 OID 26631)
-- Name: auth_user_groups auth_user_groups_user_id_6a12ed8b_fk_auth_user_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user_groups
    ADD CONSTRAINT auth_user_groups_user_id_6a12ed8b_fk_auth_user_id FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- TOC entry 3547 (class 2606 OID 26650)
-- Name: auth_user_user_permissions auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES public.auth_permission(id) DEFERRABLE INITIALLY DEFERRED;


--
-- TOC entry 3548 (class 2606 OID 26645)
-- Name: auth_user_user_permissions auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_user_user_permissions
    ADD CONSTRAINT auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- TOC entry 3549 (class 2606 OID 26666)
-- Name: django_admin_log django_admin_log_content_type_id_c4bce8eb_fk_django_co; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_content_type_id_c4bce8eb_fk_django_co FOREIGN KEY (content_type_id) REFERENCES public.django_content_type(id) DEFERRABLE INITIALLY DEFERRED;


--
-- TOC entry 3550 (class 2606 OID 26671)
-- Name: django_admin_log django_admin_log_user_id_c564eba6_fk_auth_user_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.django_admin_log
    ADD CONSTRAINT django_admin_log_user_id_c564eba6_fk_auth_user_id FOREIGN KEY (user_id) REFERENCES public.auth_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- TOC entry 3540 (class 2606 OID 26343)
-- Name: dom_usu dom_parr_fk; Type: FK CONSTRAINT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.dom_usu
    ADD CONSTRAINT dom_parr_fk FOREIGN KEY (dom_parr) REFERENCES usuarios_domi.parro(parr_id) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 3820 (class 0 OID 0)
-- Dependencies: 3540
-- Name: CONSTRAINT dom_parr_fk ON dom_usu; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON CONSTRAINT dom_parr_fk ON usuarios_domi.dom_usu IS 'campo para obtener las parroquias asignadas a cada usuario';


--
-- TOC entry 3541 (class 2606 OID 26348)
-- Name: dom_usu dom_usu_fk; Type: FK CONSTRAINT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.dom_usu
    ADD CONSTRAINT dom_usu_fk FOREIGN KEY (dom_usu) REFERENCES usuarios_dat.usuarios(usu_id) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 3821 (class 0 OID 0)
-- Dependencies: 3541
-- Name: CONSTRAINT dom_usu_fk ON dom_usu; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON CONSTRAINT dom_usu_fk ON usuarios_domi.dom_usu IS 'llave foranea para obtener el usuario correspondiente al domicilio';


--
-- TOC entry 3538 (class 2606 OID 26333)
-- Name: muni mun_est_fk; Type: FK CONSTRAINT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.muni
    ADD CONSTRAINT mun_est_fk FOREIGN KEY (mun_est) REFERENCES usuarios_domi.estados(est_id) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 3822 (class 0 OID 0)
-- Dependencies: 3538
-- Name: CONSTRAINT mun_est_fk ON muni; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON CONSTRAINT mun_est_fk ON usuarios_domi.muni IS 'llave foranea para obtener los datos del estado';


--
-- TOC entry 3539 (class 2606 OID 26338)
-- Name: parro parr_mun_fk; Type: FK CONSTRAINT; Schema: usuarios_domi; Owner: postgres
--

ALTER TABLE ONLY usuarios_domi.parro
    ADD CONSTRAINT parr_mun_fk FOREIGN KEY (parr_mun) REFERENCES usuarios_domi.muni(mun_id) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 3823 (class 0 OID 0)
-- Dependencies: 3539
-- Name: CONSTRAINT parr_mun_fk ON parro; Type: COMMENT; Schema: usuarios_domi; Owner: postgres
--

COMMENT ON CONSTRAINT parr_mun_fk ON usuarios_domi.parro IS 'llave foranea para obtener los municipios correspondientes a cada parroquia';


--
-- TOC entry 3536 (class 2606 OID 26323)
-- Name: seg_usu seg_rol_fk; Type: FK CONSTRAINT; Schema: usuarios_seg; Owner: postgres
--

ALTER TABLE ONLY usuarios_seg.seg_usu
    ADD CONSTRAINT seg_rol_fk FOREIGN KEY (seg_rol) REFERENCES usuarios_seg.roles_usu(rol_id) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- TOC entry 3824 (class 0 OID 0)
-- Dependencies: 3536
-- Name: CONSTRAINT seg_rol_fk ON seg_usu; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON CONSTRAINT seg_rol_fk ON usuarios_seg.seg_usu IS 'llave foranea para el rol del usuario';


--
-- TOC entry 3537 (class 2606 OID 26328)
-- Name: seg_usu seg_usu_fk; Type: FK CONSTRAINT; Schema: usuarios_seg; Owner: postgres
--

ALTER TABLE ONLY usuarios_seg.seg_usu
    ADD CONSTRAINT seg_usu_fk FOREIGN KEY (seg_usu) REFERENCES usuarios_dat.usuarios(usu_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- TOC entry 3825 (class 0 OID 0)
-- Dependencies: 3537
-- Name: CONSTRAINT seg_usu_fk ON seg_usu; Type: COMMENT; Schema: usuarios_seg; Owner: postgres
--

COMMENT ON CONSTRAINT seg_usu_fk ON usuarios_seg.seg_usu IS 'llave foranea para obtener los datos del usuario';


-- Completed on 2025-08-31 20:06:49 -04

--
-- PostgreSQL database dump complete
--

