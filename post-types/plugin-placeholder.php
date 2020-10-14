<?php

/**
 * Registers the `plugin_placeholder` post type.
 */
function plugin_placeholder_init()
{
    register_post_type('plugin-placeholder', array(
        'labels'                => array(
            'name'                  => __('Plugin Placeholders', 'plugin-placeholders'),
            'singular_name'         => __('Plugin Placeholders', 'plugin-placeholders'),
            'all_items'             => __('All Plugin Placeholders', 'plugin-placeholders'),
            'archives'              => __('Plugin Placeholders Archives', 'plugin-placeholders'),
            'attributes'            => __('Plugin Placeholders Attributes', 'plugin-placeholders'),
            'insert_into_item'      => __('Insert into Plugin Placeholders', 'plugin-placeholders'),
            'uploaded_to_this_item' => __('Uploaded to this Plugin Placeholders', 'plugin-placeholders'),
            'featured_image'        => _x('Featured Image', 'plugin-placeholder', 'plugin-placeholders'),
            'set_featured_image'    => _x('Set featured image', 'plugin-placeholder', 'plugin-placeholders'),
            'remove_featured_image' => _x('Remove featured image', 'plugin-placeholder', 'plugin-placeholders'),
            'use_featured_image'    => _x('Use as featured image', 'plugin-placeholder', 'plugin-placeholders'),
            'filter_items_list'     => __('Filter Plugin Placeholders list', 'plugin-placeholders'),
            'items_list_navigation' => __('Plugin Placeholders list navigation', 'plugin-placeholders'),
            'items_list'            => __('Plugin Placeholders list', 'plugin-placeholders'),
            'new_item'              => __('New Plugin Placeholders', 'plugin-placeholders'),
            'add_new'               => __('Add New', 'plugin-placeholders'),
            'add_new_item'          => __('Add New Plugin Placeholders', 'plugin-placeholders'),
            'edit_item'             => __('Edit Plugin Placeholders', 'plugin-placeholders'),
            'view_item'             => __('View Plugin Placeholders', 'plugin-placeholders'),
            'view_items'            => __('View Plugin Placeholders', 'plugin-placeholders'),
            'search_items'          => __('Search Plugin Placeholders', 'plugin-placeholders'),
            'not_found'             => __('No Plugin Placeholders found', 'plugin-placeholders'),
            'not_found_in_trash'    => __('No Plugin Placeholders found in trash', 'plugin-placeholders'),
            'parent_item_colon'     => __('Parent Plugin Placeholders:', 'plugin-placeholders'),
            'menu_name'             => __('Plugin Placeholders', 'plugin-placeholders'),
       ),
        'public'                => true,
        'hierarchical'          => false,
        'show_ui'               => true,
        'show_in_nav_menus'     => true,
        'supports'              => array('title', 'thumbnail'),
        'has_archive'           => true,
        'rewrite'               => true,
        'query_var'             => true,
        'menu_icon'             => 'dashicons-awards',
        'show_in_rest'          => true,
        'rest_base'             => 'plugin-placeholder',
        'rest_controller_class' => 'WP_REST_Posts_Controller',
    ));
}
add_action('init', 'plugin_placeholder_init');

/**
 * Sets the post updated messages for the `plugin_placeholder` post type.
 *
 * @param  array $messages Post updated messages.
 * @return array Messages for the `plugin_placeholder` post type.
 */
function plugin_placeholder_updated_messages($messages)
{
    global $post;

    $permalink = get_permalink($post);

    $messages['plugin-placeholder'] = array(
        0  => '', // Unused. Messages start at index 1.
        /* translators: %s: post permalink */
        1  => sprintf(__('Plugin Placeholders updated. <a target="_blank" href="%s">View Plugin Placeholders</a>', 'plugin-placeholders'), esc_url($permalink)),
        2  => __('Custom field updated.', 'plugin-placeholders'),
        3  => __('Custom field deleted.', 'plugin-placeholders'),
        4  => __('Plugin Placeholders updated.', 'plugin-placeholders'),
        /* translators: %s: date and time of the revision */
        5  => isset($_GET['revision']) ? sprintf(__('Plugin Placeholders restored to revision from %s', 'plugin-placeholders'), wp_post_revision_title((int) $_GET['revision'], false)) : false,
        /* translators: %s: post permalink */
        6  => sprintf(__('Plugin Placeholders published. <a href="%s">View Plugin Placeholders</a>', 'plugin-placeholders'), esc_url($permalink)),
        7  => __('Plugin Placeholders saved.', 'plugin-placeholders'),
        /* translators: %s: post permalink */
        8  => sprintf(__('Plugin Placeholders submitted. <a target="_blank" href="%s">Preview Plugin Placeholders</a>', 'plugin-placeholders'), esc_url(add_query_arg('preview', 'true', $permalink))),
        /* translators: 1: Publish box date format, see https://secure.php.net/date 2: Post permalink */
        9  => sprintf(
            __('Plugin Placeholders scheduled for: <strong>%1$s</strong>. <a target="_blank" href="%2$s">Preview Plugin Placeholders</a>', 'plugin-placeholders'),
            date_i18n(__('M j, Y @ G:i'), strtotime($post->post_date)),
            esc_url($permalink)
        ),
        /* translators: %s: post permalink */
        10 => sprintf(__('Plugin Placeholders draft updated. <a target="_blank" href="%s">Preview Plugin Placeholders</a>', 'plugin-placeholders'), esc_url(add_query_arg('preview', 'true', $permalink))),
    );

    return $messages;
}
add_filter('post_updated_messages', 'plugin_placeholder_updated_messages');
