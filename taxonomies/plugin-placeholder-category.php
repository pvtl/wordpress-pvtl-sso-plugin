<?php

/**
 * Registers the `plugin_placeholder_category` taxonomy,
 * for use with 'plugin-placeholder'.
 */
function plugin_placeholder_category_init()
{
    register_taxonomy('plugin-placeholder-category', array('plugin-placeholder'), array(
        'hierarchical'      => false,
        'public'            => true,
        'show_in_nav_menus' => true,
        'show_ui'           => true,
        'show_admin_column' => false,
        'query_var'         => true,
        'rewrite'           => true,
        'capabilities'      => array(
            'manage_terms'  => 'edit_posts',
            'edit_terms'    => 'edit_posts',
            'delete_terms'  => 'edit_posts',
            'assign_terms'  => 'edit_posts',
       ),
        'labels'            => array(
            'name'                       => __('Categories', 'plugin-placeholders'),
            'singular_name'              => _x('Categories', 'taxonomy general name', 'plugin-placeholders'),
            'search_items'               => __('Search Categories', 'plugin-placeholders'),
            'popular_items'              => __('Popular Categories', 'plugin-placeholders'),
            'all_items'                  => __('All Categories', 'plugin-placeholders'),
            'parent_item'                => __('Parent Categories', 'plugin-placeholders'),
            'parent_item_colon'          => __('Parent Categories:', 'plugin-placeholders'),
            'edit_item'                  => __('Edit Categories', 'plugin-placeholders'),
            'update_item'                => __('Update Categories', 'plugin-placeholders'),
            'view_item'                  => __('View Categories', 'plugin-placeholders'),
            'add_new_item'               => __('New Categories', 'plugin-placeholders'),
            'new_item_name'              => __('New Categories', 'plugin-placeholders'),
            'separate_items_with_commas' => __('Separate Categories with commas', 'plugin-placeholders'),
            'add_or_remove_items'        => __('Add or remove Categories', 'plugin-placeholders'),
            'choose_from_most_used'      => __('Choose from the most used Categories', 'plugin-placeholders'),
            'not_found'                  => __('No Categories found.', 'plugin-placeholders'),
            'no_terms'                   => __('No Categories', 'plugin-placeholders'),
            'menu_name'                  => __('Categories', 'plugin-placeholders'),
            'items_list_navigation'      => __('Categories list navigation', 'plugin-placeholders'),
            'items_list'                 => __('Categories list', 'plugin-placeholders'),
            'most_used'                  => _x('Most Used', 'plugin-placeholder-category', 'plugin-placeholders'),
            'back_to_items'              => __('&larr; Back to Categories', 'plugin-placeholders'),
       ),
        'show_in_rest'      => true,
        'rest_base'         => 'plugin-placeholder-category',
        'rest_controller_class' => 'WP_REST_Terms_Controller',
    ));
}
add_action('init', 'plugin_placeholder_category_init');

/**
 * Sets the post updated messages for the `plugin_placeholder_category` taxonomy.
 *
 * @param  array $messages Post updated messages.
 * @return array Messages for the `plugin_placeholder_category` taxonomy.
 */
function plugin_placeholder_category_updated_messages($messages)
{

    $messages['plugin-placeholder-category'] = array(
        0 => '', // Unused. Messages start at index 1.
        1 => __('Categories added.', 'plugin-placeholders'),
        2 => __('Categories deleted.', 'plugin-placeholders'),
        3 => __('Categories updated.', 'plugin-placeholders'),
        4 => __('Categories not added.', 'plugin-placeholders'),
        5 => __('Categories not updated.', 'plugin-placeholders'),
        6 => __('Categories deleted.', 'plugin-placeholders'),
    );

    return $messages;
}
add_filter('term_updated_messages', 'plugin_placeholder_category_updated_messages');
