#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, parse_quote, Attribute, Data, DataEnum, DataStruct, DeriveInput, Error,
    Fields, Generics, LitStr, Path, Result, WherePredicate,
};

/// Derive `sanitization::SecureSanitize` for structs and enums.
///
/// Every non-skipped field must implement `SecureSanitize`. Use
/// `#[sanitization(skip)]` only for fields that are intentionally non-secret or
/// cleared elsewhere.
///
/// # Enums
///
/// For enums, generated code can only sanitize the currently active variant.
/// It cannot safely reach bytes left behind by previously active variants after
/// a variant transition. Use `sanitization::secure_replace` before replacement,
/// derive `SecureSanitizeOnDrop` when drop-before-assignment semantics are
/// wanted, or prefer struct wrappers for high-assurance state machines.
///
/// When the `strict-enum-derive` feature is enabled on this derive crate,
/// enum derives require:
///
/// ```ignore
/// #[sanitization(enum_inactive_variant_bytes = "acknowledged")]
/// ```
#[proc_macro_derive(SecureSanitize, attributes(sanitization))]
pub fn derive_secure_sanitize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_secure_sanitize(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derive `Drop` by calling `sanitization::SecureSanitize::secure_sanitize`.
///
/// # Generics
///
/// For structs with type parameters that hold sanitizable data, the parameter
/// must carry the `SecureSanitize` bound at the type declaration:
///
/// ```ignore
/// use sanitization::SecureSanitize;
///
/// #[derive(SecureSanitize, SecureSanitizeOnDrop)]
/// struct Wrapper<T: SecureSanitize> {
///     inner: T,
/// }
/// ```
///
/// This is a Rust `Drop` restriction: the generated `Drop` impl cannot add a
/// stricter `T: SecureSanitize` bound than the struct declaration itself.
#[proc_macro_derive(SecureSanitizeOnDrop, attributes(sanitization))]
pub fn derive_secure_sanitize_on_drop(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_secure_sanitize_on_drop(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derive `sanitization::ct::ConstantTimeEq` for structs.
///
/// The generated implementation compares each non-skipped field through that
/// field's own `ConstantTimeEq` implementation and combines the hidden
/// `sanitization::ct::Choice` bits. It never compares raw struct bytes, so
/// padding and representation details are not read.
///
/// Enums and unions are rejected. For enums, inactive variant bytes cannot be
/// reached safely and comparing only the active variant can hide residual
/// secret bytes from previous variants.
#[proc_macro_derive(ConstantTimeEq, attributes(sanitization))]
pub fn derive_constant_time_eq(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_constant_time_eq(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derive `sanitization::ct::ConditionallySelectable` for structs.
///
/// The generated implementation selects every field through that field's own
/// `ConditionallySelectable` implementation. `#[sanitization(skip)]` is
/// intentionally rejected for this derive because the output must be a complete
/// selection between `left` and `right`.
///
/// Enums and unions are rejected. Field-wise struct selection avoids raw
/// representation reads and does not inspect padding bytes.
#[proc_macro_derive(ConditionallySelectable, attributes(sanitization))]
pub fn derive_conditionally_selectable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_conditionally_selectable(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[derive(Default)]
struct ContainerOptions {
    crate_path: Option<Path>,
    bound_override: Option<Vec<WherePredicate>>,
    enum_inactive_variant_bytes_acknowledged: bool,
}

#[derive(Default)]
struct FieldOptions {
    skip: bool,
    bound_override: Option<Vec<WherePredicate>>,
}

fn expand_secure_sanitize(input: &DeriveInput) -> Result<TokenStream2> {
    let options = parse_container_options(&input.attrs)?;
    let crate_path = crate_path(&options);
    let body = match &input.data {
        Data::Struct(data) => expand_struct_body(data, &crate_path)?,
        Data::Enum(data) => {
            validate_enum_options(input, &options)?;
            expand_enum_body(data, &crate_path)?
        }
        Data::Union(_) => {
            return Err(Error::new_spanned(
                input,
                "SecureSanitize cannot be derived for unions; implement it manually using documented unsafe code for the active field",
            ))
        }
    };
    let generics = add_sanitize_bounds(input.generics.clone(), &input.data, &crate_path, &options)?;
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #crate_path::SecureSanitize for #name #type_generics #where_clause {
            #[inline]
            fn secure_sanitize(&mut self) {
                #body
            }
        }
    })
}

fn validate_enum_options(input: &DeriveInput, options: &ContainerOptions) -> Result<()> {
    if cfg!(feature = "strict-enum-derive") && !options.enum_inactive_variant_bytes_acknowledged {
        return Err(Error::new_spanned(
            input,
            "SecureSanitize enum derives are rejected by the strict-enum-derive feature unless #[sanitization(enum_inactive_variant_bytes = \"acknowledged\")] is present; derived enum sanitization only clears the active variant",
        ));
    }

    Ok(())
}

fn expand_secure_sanitize_on_drop(input: &DeriveInput) -> Result<TokenStream2> {
    let options = parse_container_options(&input.attrs)?;
    let crate_path = crate_path(&options);

    if matches!(input.data, Data::Union(_)) {
        return Err(Error::new_spanned(
            input,
            "SecureSanitizeOnDrop cannot be derived for unions",
        ));
    }

    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics Drop for #name #type_generics #where_clause {
            #[inline]
            fn drop(&mut self) {
                #crate_path::SecureSanitize::secure_sanitize(self);
            }
        }
    })
}

fn expand_constant_time_eq(input: &DeriveInput) -> Result<TokenStream2> {
    let options = parse_container_options(&input.attrs)?;
    let crate_path = crate_path(&options);
    let body = match &input.data {
        Data::Struct(data) => expand_ct_eq_struct_body(data, &crate_path)?,
        Data::Enum(_) => {
            return Err(Error::new_spanned(
                input,
                "ConstantTimeEq cannot be derived for enums; compare explicit struct wrappers or implement the active-variant semantics manually",
            ))
        }
        Data::Union(_) => {
            return Err(Error::new_spanned(
                input,
                "ConstantTimeEq cannot be derived for unions; implement it manually using documented unsafe code for the active field",
            ))
        }
    };
    let trait_path: TokenStream2 = quote!(#crate_path::ct::ConstantTimeEq);
    let generics = add_trait_bounds(
        input.generics.clone(),
        &input.data,
        &trait_path,
        &options,
        SkipPolicy::Allow,
    )?;
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #crate_path::ct::ConstantTimeEq for #name #type_generics #where_clause {
            #[inline]
            fn ct_eq(&self, other: &Self) -> #crate_path::ct::Choice {
                #body
            }
        }
    })
}

fn expand_conditionally_selectable(input: &DeriveInput) -> Result<TokenStream2> {
    let options = parse_container_options(&input.attrs)?;
    let crate_path = crate_path(&options);
    let body = match &input.data {
        Data::Struct(data) => expand_ct_select_struct_body(data, &crate_path)?,
        Data::Enum(_) => {
            return Err(Error::new_spanned(
                input,
                "ConditionallySelectable cannot be derived for enums; select explicit struct wrappers or implement the active-variant semantics manually",
            ))
        }
        Data::Union(_) => {
            return Err(Error::new_spanned(
                input,
                "ConditionallySelectable cannot be derived for unions; implement it manually using documented unsafe code for the active field",
            ))
        }
    };
    let trait_path: TokenStream2 = quote!(#crate_path::ct::ConditionallySelectable);
    let generics = add_trait_bounds(
        input.generics.clone(),
        &input.data,
        &trait_path,
        &options,
        SkipPolicy::Reject,
    )?;
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #crate_path::ct::ConditionallySelectable for #name #type_generics #where_clause {
            #[inline]
            fn conditional_select(
                left: &Self,
                right: &Self,
                choice: #crate_path::ct::Choice,
            ) -> Self {
                #body
            }
        }
    })
}

fn crate_path(options: &ContainerOptions) -> Path {
    options
        .crate_path
        .clone()
        .unwrap_or_else(|| parse_quote!(::sanitization))
}

fn add_sanitize_bounds(
    mut generics: Generics,
    data: &Data,
    crate_path: &Path,
    options: &ContainerOptions,
) -> Result<Generics> {
    let where_clause = generics.make_where_clause();

    if let Some(bounds) = &options.bound_override {
        where_clause.predicates.extend(bounds.iter().cloned());
        return Ok(generics);
    }

    for field in sanitized_fields(data)? {
        let field_options = parse_field_options(&field.attrs)?;
        if field_options.skip {
            continue;
        }

        if let Some(bounds) = field_options.bound_override {
            where_clause.predicates.extend(bounds);
        } else {
            let ty = &field.ty;
            where_clause
                .predicates
                .push(parse_quote!(#ty: #crate_path::SecureSanitize));
        }
    }

    Ok(generics)
}

#[derive(Clone, Copy)]
enum SkipPolicy {
    Allow,
    Reject,
}

fn add_trait_bounds(
    mut generics: Generics,
    data: &Data,
    trait_path: &TokenStream2,
    options: &ContainerOptions,
    skip_policy: SkipPolicy,
) -> Result<Generics> {
    let where_clause = generics.make_where_clause();

    if let Some(bounds) = &options.bound_override {
        where_clause.predicates.extend(bounds.iter().cloned());
        return Ok(generics);
    }

    for field in sanitized_fields(data)? {
        let field_options = parse_field_options(&field.attrs)?;
        if field_options.skip {
            if matches!(skip_policy, SkipPolicy::Reject) {
                return Err(Error::new_spanned(
                    field,
                    "#[sanitization(skip)] is not supported for this derive because every output field must be constructed",
                ));
            }
            continue;
        }

        if let Some(bounds) = field_options.bound_override {
            where_clause.predicates.extend(bounds);
        } else {
            let ty = &field.ty;
            where_clause.predicates.push(parse_quote!(#ty: #trait_path));
        }
    }

    Ok(generics)
}

fn sanitized_fields(data: &Data) -> Result<Vec<&syn::Field>> {
    let mut fields = Vec::new();
    match data {
        Data::Struct(data) => fields.extend(data.fields.iter()),
        Data::Enum(data) => {
            for variant in &data.variants {
                fields.extend(variant.fields.iter());
            }
        }
        Data::Union(_) => {}
    }
    Ok(fields)
}

fn expand_struct_body(data: &DataStruct, crate_path: &Path) -> Result<TokenStream2> {
    let calls = field_calls_for_struct(&data.fields, crate_path)?;
    Ok(quote!(#(#calls)*))
}

fn expand_ct_eq_struct_body(data: &DataStruct, crate_path: &Path) -> Result<TokenStream2> {
    let mut calls = Vec::new();

    for (index, field) in data.fields.iter().enumerate() {
        if parse_field_options(&field.attrs)?.skip {
            continue;
        }

        let (left, right) = match &field.ident {
            Some(ident) => (quote!(&self.#ident), quote!(&other.#ident)),
            None => {
                let index = syn::Index::from(index);
                (quote!(&self.#index), quote!(&other.#index))
            }
        };
        calls.push(quote! {
            result = result & #crate_path::ct::ConstantTimeEq::ct_eq(#left, #right);
        });
    }

    Ok(quote! {
        let mut result = #crate_path::ct::Choice::TRUE;
        #(#calls)*
        result
    })
}

fn expand_ct_select_struct_body(data: &DataStruct, crate_path: &Path) -> Result<TokenStream2> {
    match &data.fields {
        Fields::Named(fields) => {
            let mut selected = Vec::new();
            for field in &fields.named {
                if parse_field_options(&field.attrs)?.skip {
                    return Err(Error::new_spanned(
                        field,
                        "#[sanitization(skip)] is not supported for ConditionallySelectable derives",
                    ));
                }
                let ident = field.ident.as_ref().expect("named field");
                selected.push(quote! {
                    #ident: #crate_path::ct::ConditionallySelectable::conditional_select(
                        &left.#ident,
                        &right.#ident,
                        choice,
                    )
                });
            }
            Ok(quote!(Self { #(#selected),* }))
        }
        Fields::Unnamed(fields) => {
            let mut selected = Vec::new();
            for (index, field) in fields.unnamed.iter().enumerate() {
                if parse_field_options(&field.attrs)?.skip {
                    return Err(Error::new_spanned(
                        field,
                        "#[sanitization(skip)] is not supported for ConditionallySelectable derives",
                    ));
                }
                let index = syn::Index::from(index);
                selected.push(quote! {
                    #crate_path::ct::ConditionallySelectable::conditional_select(
                        &left.#index,
                        &right.#index,
                        choice,
                    )
                });
            }
            Ok(quote!(Self(#(#selected),*)))
        }
        Fields::Unit => Ok(quote!(Self)),
    }
}

fn field_calls_for_struct(fields: &Fields, crate_path: &Path) -> Result<Vec<TokenStream2>> {
    let mut calls = Vec::new();

    for (index, field) in fields.iter().enumerate() {
        if parse_field_options(&field.attrs)?.skip {
            continue;
        }

        let access = match &field.ident {
            Some(ident) => quote!(&mut self.#ident),
            None => {
                let index = syn::Index::from(index);
                quote!(&mut self.#index)
            }
        };
        calls.push(quote!(#crate_path::SecureSanitize::secure_sanitize(#access);));
    }

    Ok(calls)
}

fn expand_enum_body(data: &DataEnum, crate_path: &Path) -> Result<TokenStream2> {
    let mut arms = Vec::new();

    for variant in &data.variants {
        let variant_ident = &variant.ident;
        let (pattern, calls) = match &variant.fields {
            Fields::Named(fields) => {
                let mut bindings = Vec::new();
                let mut calls = Vec::new();
                for field in &fields.named {
                    let ident = field.ident.as_ref().expect("named field");
                    if parse_field_options(&field.attrs)?.skip {
                        continue;
                    }
                    bindings.push(quote!(#ident));
                    calls.push(quote!(#crate_path::SecureSanitize::secure_sanitize(#ident);));
                }

                let pattern = if bindings.is_empty() {
                    quote!(Self::#variant_ident { .. })
                } else {
                    quote!(Self::#variant_ident { #(#bindings),*, .. })
                };
                (pattern, calls)
            }
            Fields::Unnamed(fields) => {
                let mut pattern_fields = Vec::new();
                let mut calls = Vec::new();
                for (index, field) in fields.unnamed.iter().enumerate() {
                    if parse_field_options(&field.attrs)?.skip {
                        pattern_fields.push(quote!(_));
                    } else {
                        let binding = format_ident!("field_{index}");
                        pattern_fields.push(quote!(#binding));
                        calls.push(quote!(#crate_path::SecureSanitize::secure_sanitize(#binding);));
                    }
                }
                (quote!(Self::#variant_ident(#(#pattern_fields),*)), calls)
            }
            Fields::Unit => (quote!(Self::#variant_ident), Vec::new()),
        };

        arms.push(quote!(#pattern => { #(#calls)* }));
    }

    Ok(quote! {
        match self {
            #(#arms),*
        }
    })
}

fn parse_container_options(attrs: &[Attribute]) -> Result<ContainerOptions> {
    let mut options = ContainerOptions::default();

    for attr in attrs
        .iter()
        .filter(|attr| attr.path().is_ident("sanitization"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("crate") {
                let value = meta.value()?;
                let literal: LitStr = value.parse()?;
                options.crate_path = Some(literal.parse()?);
                Ok(())
            } else if meta.path.is_ident("bound") {
                let value = meta.value()?;
                let literal: LitStr = value.parse()?;
                options.bound_override = Some(parse_bounds(&literal)?);
                Ok(())
            } else if meta.path.is_ident("enum_inactive_variant_bytes") {
                let value = meta.value()?;
                let literal: LitStr = value.parse()?;
                if literal.value() == "acknowledged" {
                    options.enum_inactive_variant_bytes_acknowledged = true;
                    Ok(())
                } else {
                    Err(meta.error("enum_inactive_variant_bytes must be exactly \"acknowledged\""))
                }
            } else {
                Err(meta.error("unsupported sanitization container attribute"))
            }
        })?;
    }

    Ok(options)
}

fn parse_field_options(attrs: &[Attribute]) -> Result<FieldOptions> {
    let mut options = FieldOptions::default();

    for attr in attrs
        .iter()
        .filter(|attr| attr.path().is_ident("sanitization"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                options.skip = true;
                Ok(())
            } else if meta.path.is_ident("bound") {
                let value = meta.value()?;
                let literal: LitStr = value.parse()?;
                options.bound_override = Some(parse_bounds(&literal)?);
                Ok(())
            } else {
                Err(meta.error("unsupported sanitization field attribute"))
            }
        })?;
    }

    Ok(options)
}

fn parse_bounds(literal: &LitStr) -> Result<Vec<WherePredicate>> {
    let text = literal.value();
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    let where_clause: syn::WhereClause = syn::parse_str(&format!("where {text}"))
        .map_err(|error| Error::new(literal.span(), error))?;
    Ok(where_clause.predicates.into_iter().collect())
}
